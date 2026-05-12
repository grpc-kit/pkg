package admin

import (
	"context"
	"sort"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/groups"
	"github.com/grpc-kit/pkg/lion/principalroles"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/usermemberships"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	principalTypeUser       = int(adminv1.PrincipalType_USER)
	principalTypeGroup      = int(adminv1.PrincipalType_GROUP)
	principalTypeDepartment = int(adminv1.PrincipalType_DEPARTMENT)

	bindingStatusActive   = int(adminv1.BindingStatus_ACTIVE)
	bindingStatusDisabled = int(adminv1.BindingStatus_DISABLED)
)

type principalDisplay struct {
	name string
	code string
}

func normalizePrincipalType(value adminv1.PrincipalType) (int, error) {
	switch value {
	case adminv1.PrincipalType_USER:
		return principalTypeUser, nil
	case adminv1.PrincipalType_GROUP:
		return principalTypeGroup, nil
	case adminv1.PrincipalType_DEPARTMENT:
		return principalTypeDepartment, nil
	default:
		return 0, errs.InvalidArgument(context.Background()).WithMessage("principal_type is required")
	}
}

func normalizeBindingStatus(value adminv1.BindingStatus) (int, error) {
	switch value {
	case adminv1.BindingStatus_BINDING_STATUS_UNSPECIFIED:
		return bindingStatusActive, nil
	case adminv1.BindingStatus_ACTIVE:
		return bindingStatusActive, nil
	case adminv1.BindingStatus_DISABLED:
		return bindingStatusDisabled, nil
	default:
		return 0, errs.InvalidArgument(context.Background()).WithMessage("invalid binding_status")
	}
}

func principalRoleMetadata(md map[string]string) map[string]string {
	if len(md) == 0 {
		return nil
	}
	dup := make(map[string]string, len(md))
	for key, value := range md {
		dup[key] = value
	}
	return dup
}

func applyBindingToPrincipalRoleCreate(cb *lion.PrincipalRolesCreate, roleID int, binding *adminv1.PrincipalRoleBinding) (*lion.PrincipalRolesCreate, error) {
	principalType, err := normalizePrincipalType(binding.GetPrincipalType())
	if err != nil {
		return nil, err
	}
	if binding.GetPrincipalId() <= 0 {
		return nil, errs.InvalidArgument(context.Background()).WithMessage("principal_id is required")
	}
	bindingStatus, err := normalizeBindingStatus(binding.GetBindingStatus())
	if err != nil {
		return nil, err
	}
	cb = cb.
		SetPrincipalType(principalType).
		SetPrincipalID(int(binding.GetPrincipalId())).
		SetRoleID(roleID).
		SetBindingStatus(bindingStatus)
	if binding.GetExpiredAt() != nil {
		cb = cb.SetExpiredAt(binding.GetExpiredAt().AsTime())
	}
	if metadata := principalRoleMetadata(binding.GetMetadata()); metadata != nil {
		cb = cb.SetMetadata(metadata)
	}
	if binding.GetDescription() != "" {
		cb = cb.SetDescription(binding.GetDescription())
	}
	return cb, nil
}

func applyBindingToPrincipalRoleUpdate(upd *lion.PrincipalRolesUpdateOne, binding *adminv1.PrincipalRoleBinding) (*lion.PrincipalRolesUpdateOne, error) {
	bindingStatus, err := normalizeBindingStatus(binding.GetBindingStatus())
	if err != nil {
		return nil, err
	}
	upd = upd.SetBindingStatus(bindingStatus)
	if binding.GetExpiredAt() != nil {
		upd = upd.SetExpiredAt(binding.GetExpiredAt().AsTime())
	} else {
		upd = upd.ClearExpiredAt()
	}
	if metadata := principalRoleMetadata(binding.GetMetadata()); metadata != nil {
		upd = upd.SetMetadata(metadata)
	} else {
		upd = upd.ClearMetadata()
	}
	upd = upd.SetDescription(binding.GetDescription())
	return upd, nil
}

func (a *KnownAdminAPI) principalRoleBindingForUpdate(ctx context.Context, db *lion.Client, roleID int, binding *adminv1.PrincipalRoleBinding) (*lion.PrincipalRoles, error) {
	principalType, err := normalizePrincipalType(binding.GetPrincipalType())
	if err != nil {
		return nil, err
	}
	if binding.GetId() > 0 {
		row, err := db.PrincipalRoles.Get(ctx, int(binding.GetId()))
		if err != nil {
			if lion.IsNotFound(err) {
				return nil, errs.NotFound(ctx).WithMessage("principal role binding not found")
			}
			return nil, err
		}
		if row.RoleID != roleID {
			return nil, errs.InvalidArgument(ctx).WithMessage("binding id does not belong to this role")
		}
		if int(binding.GetPrincipalId()) > 0 && row.PrincipalID != int(binding.GetPrincipalId()) {
			return nil, errs.InvalidArgument(ctx).WithMessage("principal_id does not match binding record")
		}
		if row.PrincipalType != principalType {
			return nil, errs.InvalidArgument(ctx).WithMessage("principal_type does not match binding record")
		}
		return row, nil
	}
	if binding.GetPrincipalId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("binding id or principal_id is required")
	}
	row, err := db.PrincipalRoles.Query().
		Where(
			principalroles.RoleIDEQ(roleID),
			principalroles.PrincipalTypeEQ(principalType),
			principalroles.PrincipalIDEQ(int(binding.GetPrincipalId())),
		).
		Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("principal role binding not found")
		}
		return nil, err
	}
	return row, nil
}

func principalRoleBindingToProto(binding *lion.PrincipalRoles, display principalDisplay) *adminv1.PrincipalRoleBinding {
	if binding == nil {
		return nil
	}
	result := &adminv1.PrincipalRoleBinding{
		Id:            int64(binding.ID),
		PrincipalType: adminv1.PrincipalType(binding.PrincipalType),
		PrincipalId:   int64(binding.PrincipalID),
		PrincipalName: display.name,
		PrincipalCode: display.code,
		RoleId:        int64(binding.RoleID),
		BindingStatus: adminv1.BindingStatus(binding.BindingStatus),
		Description:   binding.Description,
		CreatedBy:     binding.CreatedBy,
		UpdatedBy:     binding.UpdatedBy,
		CreatedAt:     timestamppb.New(binding.CreatedAt),
		UpdatedAt:     timestamppb.New(binding.UpdatedAt),
	}
	if !binding.ExpiredAt.IsZero() {
		result.ExpiredAt = timestamppb.New(binding.ExpiredAt)
	}
	if len(binding.Metadata) > 0 {
		result.Metadata = principalRoleMetadata(binding.Metadata)
	}
	return result
}

func bindingStatusToMembershipStatus(status int) adminv1.Membership_Status {
	switch status {
	case bindingStatusActive:
		return adminv1.Membership_ACTIVE
	case bindingStatusDisabled:
		return adminv1.Membership_DISABLED
	default:
		return adminv1.Membership_STATUS_UNSPECIFIED
	}
}

func principalRoleToDirectUserMembership(binding *lion.PrincipalRoles, user *lion.Users) *adminv1.Membership {
	if binding == nil || user == nil {
		return nil
	}
	member := newMembershipProto(
		binding.ID,
		user.ID,
		adminv1.Membership_ROLE,
		binding.RoleID,
		0,
		int(bindingStatusToMembershipStatus(binding.BindingStatus)),
		0,
		nil,
		membershipTimestamp(binding.ExpiredAt),
		binding.CreatedBy,
		binding.UpdatedBy,
		membershipTimestamp(binding.CreatedAt),
		membershipTimestamp(binding.UpdatedAt),
		binding.Description,
	)
	applyMembershipUser(member, user)
	if len(binding.Metadata) > 0 {
		member.Metadata = principalRoleMetadata(binding.Metadata)
	}
	return member
}

func isPrincipalRoleActive(binding *lion.PrincipalRoles, now time.Time) bool {
	if binding == nil {
		return false
	}
	if binding.BindingStatus != bindingStatusActive {
		return false
	}
	if !binding.ExpiredAt.IsZero() && !binding.ExpiredAt.After(now) {
		return false
	}
	return true
}

func loadPrincipalDisplays(ctx context.Context, db *lion.Client, bindings []*lion.PrincipalRoles) (map[int]map[int]principalDisplay, error) {
	result := map[int]map[int]principalDisplay{
		principalTypeUser:       {},
		principalTypeGroup:      {},
		principalTypeDepartment: {},
	}

	userIDs := make([]int, 0)
	groupIDs := make([]int, 0)
	departmentIDs := make([]int, 0)
	seenUsers := map[int]struct{}{}
	seenGroups := map[int]struct{}{}
	seenDepartments := map[int]struct{}{}

	for _, binding := range bindings {
		switch binding.PrincipalType {
		case principalTypeUser:
			if _, ok := seenUsers[binding.PrincipalID]; !ok {
				seenUsers[binding.PrincipalID] = struct{}{}
				userIDs = append(userIDs, binding.PrincipalID)
			}
		case principalTypeGroup:
			if _, ok := seenGroups[binding.PrincipalID]; !ok {
				seenGroups[binding.PrincipalID] = struct{}{}
				groupIDs = append(groupIDs, binding.PrincipalID)
			}
		case principalTypeDepartment:
			if _, ok := seenDepartments[binding.PrincipalID]; !ok {
				seenDepartments[binding.PrincipalID] = struct{}{}
				departmentIDs = append(departmentIDs, binding.PrincipalID)
			}
		}
	}

	if len(userIDs) > 0 {
		rows, err := db.Users.Query().
			Select(users.FieldID, users.FieldUsername, users.FieldNickname).
			Where(users.IDIn(userIDs...)).
			All(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			name := row.Nickname
			if name == "" {
				name = row.Username
			}
			result[principalTypeUser][row.ID] = principalDisplay{name: name, code: row.Username}
		}
	}

	if len(groupIDs) > 0 {
		rows, err := db.Groups.Query().
			Select(groups.FieldID, groups.FieldCode, groups.FieldDisplayName).
			Where(groups.IDIn(groupIDs...)).
			All(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			result[principalTypeGroup][row.ID] = principalDisplay{name: row.DisplayName, code: row.Code}
		}
	}

	if len(departmentIDs) > 0 {
		rows, err := db.Departments.Query().
			Select(departments.FieldID, departments.FieldCode, departments.FieldDisplayName).
			Where(departments.IDIn(departmentIDs...)).
			All(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			result[principalTypeDepartment][row.ID] = principalDisplay{name: row.DisplayName, code: row.Code}
		}
	}

	return result, nil
}

func expandPrincipalRoleBindingsToMembers(ctx context.Context, db *lion.Client, bindings []*lion.PrincipalRoles) ([]*adminv1.Membership, error) {
	now := time.Now()
	groupIDs := make([]int, 0)
	departmentIDs := make([]int, 0)
	directUserIDs := make([]int, 0)
	seenGroupIDs := map[int]struct{}{}
	seenDepartmentIDs := map[int]struct{}{}
	seenUserIDs := map[int]struct{}{}
	directBindings := make([]*lion.PrincipalRoles, 0)

	for _, binding := range bindings {
		if !isPrincipalRoleActive(binding, now) {
			continue
		}
		switch binding.PrincipalType {
		case principalTypeUser:
			directBindings = append(directBindings, binding)
			if _, ok := seenUserIDs[binding.PrincipalID]; !ok {
				seenUserIDs[binding.PrincipalID] = struct{}{}
				directUserIDs = append(directUserIDs, binding.PrincipalID)
			}
		case principalTypeGroup:
			if _, ok := seenGroupIDs[binding.PrincipalID]; !ok {
				seenGroupIDs[binding.PrincipalID] = struct{}{}
				groupIDs = append(groupIDs, binding.PrincipalID)
			}
		case principalTypeDepartment:
			if _, ok := seenDepartmentIDs[binding.PrincipalID]; !ok {
				seenDepartmentIDs[binding.PrincipalID] = struct{}{}
				departmentIDs = append(departmentIDs, binding.PrincipalID)
			}
		}
	}

	result := make([]*adminv1.Membership, 0)

	if len(directBindings) > 0 {
		userMap := map[int]*lion.Users{}
		rows, err := db.Users.Query().
			Select(users.FieldID, users.FieldUsername, users.FieldNickname).
			Where(users.IDIn(directUserIDs...)).
			All(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			userMap[row.ID] = row
		}
		for _, binding := range directBindings {
			if user := userMap[binding.PrincipalID]; user != nil {
				result = append(result, principalRoleToDirectUserMembership(binding, user))
			}
		}
	}

	if len(groupIDs) > 0 {
		rows, err := db.UserMemberships.Query().
			Where(
				usermemberships.TargetTypeEQ(membershipTargetGroup),
				usermemberships.TargetIDIn(groupIDs...),
			).
			WithLionUsers(func(query *lion.UsersQuery) {
				query.Select(users.FieldID, users.FieldUsername, users.FieldNickname)
			}).
			All(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			result = append(result, userMembershipToProto(row))
		}
	}

	if len(departmentIDs) > 0 {
		rows, err := db.UserMemberships.Query().
			Where(
				usermemberships.TargetTypeEQ(membershipTargetDepartment),
				usermemberships.TargetIDIn(departmentIDs...),
			).
			WithLionUsers(func(query *lion.UsersQuery) {
				query.Select(users.FieldID, users.FieldUsername, users.FieldNickname)
			}).
			All(ctx)
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			result = append(result, userMembershipToProto(row))
		}
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Id != result[j].Id {
			return result[i].Id > result[j].Id
		}
		if result[i].UserId != result[j].UserId {
			return result[i].UserId < result[j].UserId
		}
		return result[i].TargetId < result[j].TargetId
	})

	return result, nil
}

func effectiveRoleIDsForUser(ctx context.Context, db *lion.Client, userID int) ([]int, error) {
	now := time.Now()
	roleIDs := map[int]struct{}{}

	collect := func(principalType int, principalIDs []int) error {
		if len(principalIDs) == 0 {
			return nil
		}
		rows, err := db.PrincipalRoles.Query().
			Where(
				principalroles.PrincipalTypeEQ(principalType),
				principalroles.PrincipalIDIn(principalIDs...),
				principalroles.BindingStatusEQ(bindingStatusActive),
				principalroles.Or(
					principalroles.ExpiredAtIsNil(),
					principalroles.ExpiredAtGT(now),
				),
			).
			All(ctx)
		if err != nil {
			return err
		}
		for _, row := range rows {
			roleIDs[row.RoleID] = struct{}{}
		}
		return nil
	}

	if err := collect(principalTypeUser, []int{userID}); err != nil {
		return nil, err
	}

	groupMemberships, err := db.UserMemberships.Query().
		Select(usermemberships.FieldTargetID).
		Where(
			usermemberships.UserIDEQ(userID),
			usermemberships.TargetTypeEQ(membershipTargetGroup),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}
	groupIDs := make([]int, 0, len(groupMemberships))
	for _, row := range groupMemberships {
		groupIDs = append(groupIDs, row.TargetID)
	}
	if err := collect(principalTypeGroup, groupIDs); err != nil {
		return nil, err
	}

	departmentMemberships, err := db.UserMemberships.Query().
		Select(usermemberships.FieldTargetID).
		Where(
			usermemberships.UserIDEQ(userID),
			usermemberships.TargetTypeEQ(membershipTargetDepartment),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}
	departmentIDs := make([]int, 0, len(departmentMemberships))
	for _, row := range departmentMemberships {
		departmentIDs = append(departmentIDs, row.TargetID)
	}
	if err := collect(principalTypeDepartment, departmentIDs); err != nil {
		return nil, err
	}

	result := make([]int, 0, len(roleIDs))
	for roleID := range roleIDs {
		result = append(result, roleID)
	}
	sort.Ints(result)
	return result, nil
}

func roleCodesForIDs(ctx context.Context, db *lion.Client, roleIDs []int) ([]string, error) {
	if len(roleIDs) == 0 {
		return []string{}, nil
	}
	rows, err := db.Roles.Query().
		Select(roles.FieldID, roles.FieldCode).
		Where(roles.IDIn(roleIDs...)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(rows))
	for _, row := range rows {
		result = append(result, row.Code)
	}
	sort.Strings(result)
	return result, nil
}