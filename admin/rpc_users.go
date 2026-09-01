package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/groups"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/usermemberships"
	"github.com/grpc-kit/pkg/lion/users"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	permissionUsersList          = "users.list"
	permissionUsersSensitiveGet  = "users.sensitive.get"
	permissionUsersGet           = "users.get"
	permissionUsersCreate        = "users.create"
	permissionUsersUpdate        = "users.update"
	permissionUsersPasswordReset = "users.password.reset"
)

// requireUserManagePermission 是用户管理 RPC 的 handler 级纵深授权。
// Phase 0 先把独立 permission code 映射到内置管理角色；后续接入动态策略时，
// handler 调用点及审计 action 无需再次调整。
func (a *KnownAdminAPI) requireUserManagePermission(ctx context.Context, permission string) (int64, error) {
	userID, err := GetUserID(ctx)
	if err != nil || userID <= 0 {
		return 0, errs.PermissionDenied(ctx).WithMessage("not found user id")
	}

	roleCodes, ok := rpc.GetRolesFromContext(ctx)
	if !ok {
		return 0, errs.PermissionDenied(ctx).WithMessage(fmt.Sprintf("permission %s is required", permission))
	}
	for _, roleCode := range roleCodes {
		switch strings.TrimSpace(roleCode) {
		case seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN), seedRoleCode(adminv1.RoleCode_ROLE_CODE_ADMIN):
			return userID, nil
		}
	}

	return 0, errs.PermissionDenied(ctx).WithMessage(fmt.Sprintf("permission %s is required", permission))
}

func isSupportedGender(g adminv1.User_Gender) bool {
	switch g {
	case adminv1.User_GENDER_UNSPECIFIED, adminv1.User_MALE, adminv1.User_FEMALE, adminv1.User_OTHER, adminv1.User_PRIVATE:
		return true
	default:
		return false
	}
}

// phoneNumberComplete 表示国家码与本地号码均已提供，才持久化加密与哈希。
func phoneNumberComplete(pn *adminv1.PhoneNumber) bool {
	if pn == nil {
		return false
	}
	return strings.TrimSpace(pn.GetCountryCode()) != "" && strings.TrimSpace(pn.GetNationalNumber()) != ""
}

// validateCreateUserVerificationState prevents a verification flag from being
// persisted without the contact value it is supposed to attest to.
func validateCreateUserVerificationState(user *adminv1.User) error {
	if user.GetEmailVerified() && strings.TrimSpace(user.GetEmail()) == "" {
		return fmt.Errorf("email_verified requires email")
	}
	if user.GetPhoneNumberVerified() && !phoneNumberComplete(user.GetPhoneNumber()) {
		return fmt.Errorf("phone_number_verified requires a complete phone_number")
	}
	return nil
}

// isServerManagedUserField 表示由服务端写入、不接受调用方通过 update_mask 指定的字段。
// email_verified 与 phone_number_verified 不在此列：管理端允许人工置位，
// 由 UpdateUser 内的联系方式变更重置逻辑保证一致性。
func isServerManagedUserField(path string) bool {
	switch path {
	case users.FieldCreatedBy, users.FieldUpdatedBy,
		users.FieldCreatedAt, users.FieldUpdatedAt, users.FieldDeletedAt:
		return true
	default:
		return false
	}
}

func (a *KnownAdminAPI) decryptStringField(ctx context.Context, fieldName string, encrypted []byte) (string, error) {
	if len(encrypted) == 0 {
		return "", nil
	}
	raw, err := crypto.DecryptAES(a.config.aesKey, encrypted)
	if err != nil {
		return "", errs.Internal(ctx).WithMessage(fmt.Sprintf("decrypt %s failed", fieldName)).Err()
	}
	return string(raw), nil
}

func (a *KnownAdminAPI) decryptPhoneNumberField(ctx context.Context, encrypted []byte) (*adminv1.PhoneNumber, error) {
	if len(encrypted) == 0 {
		return nil, nil
	}
	raw, err := crypto.DecryptAES(a.config.aesKey, encrypted)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("decrypt phone_number failed").Err()
	}
	pn := &adminv1.PhoneNumber{}
	if err := proto.Unmarshal(raw, pn); err != nil {
		return nil, errs.Internal(ctx).WithMessage("decode phone_number failed").Err()
	}
	return pn, nil
}

func (a *KnownAdminAPI) decryptAddressField(ctx context.Context, encrypted []byte) (*adminv1.Address, error) {
	if len(encrypted) == 0 {
		return nil, nil
	}
	raw, err := crypto.DecryptAES(a.config.aesKey, encrypted)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("decrypt address failed").Err()
	}
	address := &adminv1.Address{}
	if err := proto.Unmarshal(raw, address); err != nil {
		return nil, errs.Internal(ctx).WithMessage("decode address failed").Err()
	}
	return address, nil
}

func (a *KnownAdminAPI) toAdminUser(ctx context.Context, user *lion.Users, includeSensitive bool) (*adminv1.User, error) {
	if user == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("user is nil").Err()
	}

	var birthday *timestamppb.Timestamp
	if user.Birthdate != nil {
		birthday = timestamppb.New(*user.Birthdate)
	}
	var deletedAt *timestamppb.Timestamp
	if user.DeletedAt != nil {
		deletedAt = timestamppb.New(*user.DeletedAt)
	}

	resp := &adminv1.User{
		Id:                  int64(user.ID),
		Username:            user.Username,
		Type:                adminv1.User_Type(user.UserType),
		Status:              adminv1.User_Status(user.UserStatus),
		Nickname:            user.Nickname,
		Profile:             user.Profile,
		Picture:             user.Picture,
		Website:             user.Website,
		Gender:              adminv1.User_Gender(user.Gender),
		Birthday:            birthday,
		Timezone:            user.Timezone,
		Locale:              user.Locale,
		EmailVerified:       user.EmailVerified,
		PhoneNumberVerified: user.PhoneNumberVerified,
		CreatedAt:           timestamppb.New(user.CreatedAt),
		UpdatedAt:           timestamppb.New(user.UpdatedAt),
		DeletedAt:           deletedAt,
		CreatedBy:           user.CreatedBy,
		UpdatedBy:           user.UpdatedBy,
		Metadata:            user.Metadata,
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("not found database client").Err()
	}
	mfaEnabled, err := db.UserIdentities.Query().
		Where(
			useridentities.UserIDEQ(user.ID),
			useridentities.MfaEnabledEQ(true),
		).
		Exist(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("query user mfa status failed").Err()
	}
	resp.MfaEnabled = mfaEnabled

	if includeSensitive {
		depMembers, err := db.UserMemberships.Query().
			Where(
				usermemberships.UserIDEQ(user.ID),
				usermemberships.TargetTypeEQ(membershipTargetDepartment),
			).
			Order(lion.Asc(usermemberships.FieldMemberType), lion.Asc(usermemberships.FieldTargetID)).
			All(ctx)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage("query user department memberships failed").Err()
		}
		departmentMap := map[int]*lion.Departments{}
		if len(depMembers) > 0 {
			departmentIDs := make([]int, 0, len(depMembers))
			for _, item := range depMembers {
				departmentIDs = append(departmentIDs, item.TargetID)
			}
			depTargets, err := db.Departments.Query().
				Where(departments.IDIn(departmentIDs...), departments.DeletedAtIsNil()).
				All(ctx)
			if err != nil {
				return nil, errs.Internal(ctx).WithMessage("query user department targets failed").Err()
			}
			for _, item := range depTargets {
				departmentMap[item.ID] = item
			}
		}
		resp.DepartmentMembers = make([]*adminv1.Membership, 0, len(depMembers))
		for _, item := range depMembers {
			target := departmentMap[item.TargetID]
			if target == nil {
				continue
			}
			membership := userMembershipToProto(item)
			applyMembershipTargetName(membership, target.DisplayName, target.Code)
			resp.DepartmentMembers = append(resp.DepartmentMembers, membership)
		}

		grpMembers, err := db.UserMemberships.Query().
			Where(
				usermemberships.UserIDEQ(user.ID),
				usermemberships.TargetTypeEQ(membershipTargetGroup),
			).
			Order(lion.Asc(usermemberships.FieldJoinedAt), lion.Asc(usermemberships.FieldTargetID)).
			All(ctx)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage("query user group memberships failed").Err()
		}
		groupMap := map[int]*lion.Groups{}
		if len(grpMembers) > 0 {
			groupIDs := make([]int, 0, len(grpMembers))
			for _, item := range grpMembers {
				groupIDs = append(groupIDs, item.TargetID)
			}
			groupTargets, err := db.Groups.Query().
				Where(groups.IDIn(groupIDs...), groups.DeletedAtIsNil()).
				All(ctx)
			if err != nil {
				return nil, errs.Internal(ctx).WithMessage("query user group targets failed").Err()
			}
			for _, item := range groupTargets {
				groupMap[item.ID] = item
			}
		}
		resp.GroupMembers = make([]*adminv1.Membership, 0, len(grpMembers))
		for _, item := range grpMembers {
			target := groupMap[item.TargetID]
			if target == nil {
				continue
			}
			membership := userMembershipToProto(item)
			applyMembershipTargetName(membership, target.DisplayName, target.Code)
			resp.GroupMembers = append(resp.GroupMembers, membership)
		}
	}

	if !includeSensitive {
		return resp, nil
	}

	realname, err := a.decryptStringField(ctx, users.FieldRealnameEncrypted, user.RealnameEncrypted)
	if err != nil {
		return nil, err
	}
	nationalID, err := a.decryptStringField(ctx, users.FieldNationalIDEncrypted, user.NationalIDEncrypted)
	if err != nil {
		return nil, err
	}
	email, err := a.decryptStringField(ctx, users.FieldEmailEncrypted, user.EmailEncrypted)
	if err != nil {
		return nil, err
	}
	phoneNumber, err := a.decryptPhoneNumberField(ctx, user.PhoneNumberEncrypted)
	if err != nil {
		return nil, err
	}
	address, err := a.decryptAddressField(ctx, user.AddressEncrypted)
	if err != nil {
		return nil, err
	}

	resp.Realname = realname
	resp.NationalId = nationalID
	resp.Email = email
	resp.PhoneNumber = phoneNumber
	resp.Address = address

	return resp, nil
}

// CreateUser 创建用户
func (a *KnownAdminAPI) CreateUser(ctx context.Context, req *adminv1.CreateUserRequest) (*adminv1.User, error) {
	if req == nil || req.User == nil {
		return nil, errs.InvalidArgument(ctx).
			WithMessage("request body user is nil")
	}

	if req.User.GetUsername() == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("username is empty")
	}
	userIDInt, err := a.requireUserManagePermission(ctx, permissionUsersCreate)
	if err != nil {
		return nil, err
	}
	if !isSupportedGender(req.User.GetGender()) {
		return nil, errs.InvalidArgument(ctx).WithMessage("gender is out of supported range")
	}
	if err := validateCreateUserVerificationState(req.User); err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	timezone, locale, err := normalizeUserLocaleFields(req.User.GetTimezone(), req.User.GetLocale())
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}

	unassignedDept, err := queryBuiltinDepartment(
		ctx,
		tx,
		seedDepartmentCode(adminv1.DepartmentCode_DEPARTMENT_CODE_UNASSIGNED),
	)
	if err != nil {
		_ = tx.Rollback()
		if lion.IsNotFound(err) {
			return nil, errs.FailedPrecondition(ctx).
				WithMessage("unassigned department not found, run database initialize").
				WithDetails(&errdetails.LocalizedMessage{
					Locale:  "zh-CN",
					Message: "未找到默认待分配部门，请先完成数据库初始化。",
				}).Err()
		}
		return nil, err
	}

	userCreate := tx.Users.Create()
	userCreate.SetUsername(req.User.GetUsername())
	userCreate.SetCreatedBy(userIDInt)
	userCreate.SetUpdatedBy(userIDInt)
	userCreate.SetUserType(int(req.User.GetType()))
	userCreate.SetUserStatus(int(req.User.GetStatus()))
	userCreate.SetGender(int(req.User.GetGender()))
	userCreate.SetTimezone(timezone)
	userCreate.SetLocale(locale)
	if req.User.GetMetadata() != nil {
		userCreate.SetMetadata(req.User.GetMetadata())
	}
	if req.User.GetBirthday() != nil {
		userCreate.SetBirthdate(req.User.GetBirthday().AsTime())
	}

	if req.User.GetRealname() != "" {
		realname, err := crypto.EncryptAES(a.config.aesKey, []byte(req.User.GetRealname()))
		if err != nil {
			return nil, err
		}
		userCreate.SetRealnameEncrypted(realname)
	}
	if req.User.GetNationalId() != "" {
		idcard, err := crypto.EncryptAES(a.config.aesKey, []byte(req.User.GetNationalId()))
		if err != nil {
			return nil, err
		}
		userCreate.SetNationalIDEncrypted(idcard)
		userCreate.SetNationalIDHash(crypto.SHA256([]byte(req.User.GetNationalId())))
	}
	if req.GetUser().GetNickname() != "" {
		userCreate.SetNickname(req.GetUser().GetNickname())
	}
	if req.GetUser().GetProfile() != "" {
		userCreate.SetProfile(req.GetUser().GetProfile())
	}
	if req.GetUser().GetPicture() != "" {
		userCreate.SetPicture(req.GetUser().GetPicture())
	}
	if req.GetUser().GetWebsite() != "" {
		userCreate.SetWebsite(req.GetUser().GetWebsite())
	}
	if req.GetUser().Email != "" {
		identifier, err := canonicalizeEmailIdentifier(req.GetUser().GetEmail())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage("invalid email format")
		}
		email, err := crypto.EncryptAES(a.config.aesKey, []byte(identifier.StoredValue))
		if err != nil {
			return nil, err
		}
		userCreate.SetEmailEncrypted(email)
		userCreate.SetEmailHash(identifier.Hash)
		userCreate.SetEmailVerified(req.GetUser().GetEmailVerified())
	}
	if phoneNumberComplete(req.GetUser().GetPhoneNumber()) {
		identifier, err := canonicalizePhoneNumberIdentifier(req.GetUser().GetPhoneNumber())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
		}
		tmp, err := proto.Marshal(req.GetUser().GetPhoneNumber())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage("invalid phone_number format")
		}
		phoneNumber, err := crypto.EncryptAES(a.config.aesKey, tmp)
		if err != nil {
			return nil, err
		}
		userCreate.SetPhoneNumberEncrypted(phoneNumber)
		userCreate.SetPhoneNumberHash(identifier.Hash)
		userCreate.SetPhoneNumberVerified(req.GetUser().GetPhoneNumberVerified())
	}
	if req.GetUser().GetAddress() != nil {
		rawAddress, err := proto.Marshal(req.GetUser().GetAddress())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage("invalid address format")
		}
		encAddress, err := crypto.EncryptAES(a.config.aesKey, rawAddress)
		if err != nil {
			return nil, err
		}
		userCreate.SetAddressEncrypted(encAddress)
	}
	thisUser, err := userCreate.Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		if strings.Contains(err.Error(), "duplicate key value") {
			return nil, errs.AlreadyExists(ctx).
				WithLogger(a.logger, "create user err: %v", err).
				WithMessage("user already exists").
				WithMessageZHCN("你好，已存在!").Err()
		}

		return nil, errs.InvalidArgument(ctx).
			WithMessage("user create fail.").
			WithDetails(&errdetails.LocalizedMessage{Locale: "zh-CN", Message: "创建用户失败！"}).Err()
	}

	_, err = tx.UserMemberships.Create().
		SetUserID(thisUser.ID).
		SetTargetType(membershipTargetDepartment).
		SetTargetID(unassignedDept.ID).
		SetMemberRole(int(adminv1.Membership_MEMBER)).
		SetMemberStatus(int(adminv1.Membership_ACTIVE)).
		SetMemberType(int(adminv1.Membership_PRIMARY)).
		SetCreatedBy(userIDInt).
		SetUpdatedBy(userIDInt).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	row, err := a.config.db.Users.Query().
		Where(users.IDEQ(thisUser.ID)).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return a.toAdminUser(ctx, row, true)
}

// ListUsers 获取用户列表
func (a *KnownAdminAPI) ListUsers(ctx context.Context, req *adminv1.ListUsersRequest) (*adminv1.ListUsersResponse, error) {
	if req == nil {
		req = &adminv1.ListUsersRequest{}
	}
	if _, err := a.requireUserManagePermission(ctx, permissionUsersList); err != nil {
		return nil, err
	}
	if req.GetView() == adminv1.ListUsersRequest_USER_VIEW_FULL {
		if _, err := a.requireUserManagePermission(ctx, permissionUsersSensitiveGet); err != nil {
			return nil, err
		}
	}
	deletedOnly, err := listUsersDeletedOnly(req)
	if err != nil {
		return nil, err
	}

	result := &adminv1.ListUsersResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	var selectViewFields []string

	basicViewFields := []string{
		users.FieldID,
		users.FieldUsername,
		users.FieldUserType,
		users.FieldUserStatus,
		users.FieldNickname,
		users.FieldProfile,
		users.FieldPicture,
		users.FieldWebsite,
		users.FieldTimezone,
		users.FieldLocale,
		users.FieldCreatedBy,
		users.FieldUpdatedBy,
		users.FieldCreatedAt,
		users.FieldUpdatedAt,
		users.FieldDeletedAt,
		users.FieldMetadata,
	}

	fullViewFields := append(basicViewFields, []string{
		users.FieldRealnameEncrypted,
		users.FieldNationalIDEncrypted,
		users.FieldEmailEncrypted,
		users.FieldEmailVerified,
		users.FieldGender,
		users.FieldBirthdate,
		users.FieldPhoneNumberEncrypted,
		users.FieldPhoneNumberVerified,
		users.FieldAddressEncrypted,
		users.FieldNationalIDHash,
		users.FieldEmailHash,
		users.FieldPhoneNumberHash,
		users.FieldDescription,
	}...)

	switch req.GetView() {
	case adminv1.ListUsersRequest_USER_VIEW_FULL:
		selectViewFields = fullViewFields
	default:
		selectViewFields = basicViewFields
	}

	// 查找用户并实现分页
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	var lastID int
	if req.GetPageToken() != "" {
		data, err := base64.StdEncoding.DecodeString(req.GetPageToken())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage("invalid page_token")
		}
		if err := json.Unmarshal(data, &lastID); err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage("invalid page_token format")
		}
	}

	userQuery := db.Users.Query()

	// 是否有过滤属性
	if req.GetFilterId() != "" {
		uid, err := strconv.Atoi(req.GetFilterId())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage("invalid filter_id")
		}

		userQuery = userQuery.Where(users.IDEQ(uid))
	}
	if req.GetFilterUsername() != "" {
		userQuery = userQuery.Where(users.UsernameContains(req.GetFilterUsername()))
	}
	if req.GetFilterNickname() != "" {
		userQuery = userQuery.Where(users.NicknameContains(req.GetFilterNickname()))
	}
	if req.GetFilterStatus() != "" {
		status, err := strconv.Atoi(req.GetFilterStatus())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage("invalid filter_status")
		}
		userQuery = userQuery.Where(users.UserStatusEQ(status))
	}
	if deletedOnly {
		userQuery = userQuery.Where(users.DeletedAtNotNil())
	}
	if !req.GetShowDeleted() {
		userQuery = userQuery.Where(users.DeletedAtIsNil())
	}

	// OrderBy，游标分页只支持默认 ID 倒序，避免排序字段与游标条件不一致。
	cursorByIDDesc := true
	if req.GetOrderBy() != "" {
		switch req.GetOrderBy() {
		case "create_time desc":
			cursorByIDDesc = false
			userQuery = userQuery.Order(lion.Desc(users.FieldCreatedAt))
		case "create_time asc":
			cursorByIDDesc = false
			userQuery = userQuery.Order(lion.Asc(users.FieldCreatedAt))
		case "nickname asc":
			cursorByIDDesc = false
			userQuery = userQuery.Order(lion.Asc(users.FieldNickname))
		case "nickname desc":
			cursorByIDDesc = false
			userQuery = userQuery.Order(lion.Desc(users.FieldNickname))
		default:
			userQuery = userQuery.Order(lion.Desc(users.FieldID))
		}
	} else {
		userQuery = userQuery.Order(lion.Desc(users.FieldID))
	}

	totalSize, err := userQuery.Count(ctx)
	if err != nil {
		return nil, err
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListUsersRequest_Offset:
		// Offset 分页
		userQuery = userQuery.Offset(int(p.Offset))
	case *adminv1.ListUsersRequest_PageToken:
		if !cursorByIDDesc {
			return nil, errs.InvalidArgument(ctx).WithMessage("page_token only supports default id-desc sorting")
		}
		// Cursor 分页
		if lastID > 0 {
			userQuery = userQuery.Where(users.IDLT(lastID))
		}
	}

	userQuery = userQuery.Limit(pageSize)

	searchUsers, err := userQuery.Select(selectViewFields...).All(ctx)
	if err != nil {
		return nil, err
	}

	// --- 构造 next_page_token ---
	var nextPageToken string
	if len(searchUsers) == pageSize {
		last := searchUsers[len(searchUsers)-1].ID
		tokenData, _ := json.Marshal(last)
		nextPageToken = base64.StdEncoding.EncodeToString(tokenData)
	}

	result.NextPageToken = nextPageToken
	result.TotalSize = int32(totalSize)

	includeSensitive := req.GetView() == adminv1.ListUsersRequest_USER_VIEW_FULL
	for _, user := range searchUsers {
		respUser, err := a.toAdminUser(ctx, user, includeSensitive)
		if err != nil {
			return nil, err
		}
		result.Users = append(result.Users, respUser)
	}

	return result, nil
}

// listUsersDeletedOnly implements the minimum AIP-160 subset required by the
// recycle bin while retaining show_deleted's existing "include deleted"
// semantics for normal management lists.
func listUsersDeletedOnly(req *adminv1.ListUsersRequest) (bool, error) {
	filter := strings.TrimSpace(req.GetFilter())
	if filter == "" {
		return false, nil
	}
	if filter != "deleted_at != null" {
		return false, errs.InvalidArgument(context.Background()).WithMessage("unsupported filter")
	}
	if !req.GetShowDeleted() {
		return false, errs.InvalidArgument(context.Background()).WithMessage("deleted_at filter requires show_deleted=true")
	}
	return true, nil
}

// ListUsersV1 列出用户列表
/*
func (a *KnownAdminAPI) ListUsersV1(ctx context.Context, req *adminv1.ListUsersRequest) (*adminv1.ListUsersResponse, error) {
	result := &adminv1.ListUsersResponse{}

	var selectViewFields []string

	basicViewFields := []string{
		users.FieldID,
		users.FieldUsername,
		users.FieldStatus,
		users.FieldNickname,
		users.FieldProfile,
		users.FieldPicture,
		users.FieldWebsite,
		users.FieldZoneinfo,
		users.FieldLocale,
		users.FieldCreatedAt,
		users.FieldUpdatedAt,
	}

	fullViewFields := append(basicViewFields, []string{
		users.FieldRealnameEncrypted,
		users.FieldNationalIDEncrypted,
		users.FieldEmailEncrypted,
		users.FieldEmailVerified,
		users.FieldGender,
		users.FieldBirthdate,
		users.FieldPhoneNumberEncrypted,
		users.FieldPhoneNumberVerified,
		users.FieldAddressEncrypted,
		// users.FieldDepartmentID,
		users.FieldDescription,
	}...)

	switch req.GetView() {
	case adminv1.ListUsersRequest_USER_VIEW_FULL:
		selectViewFields = fullViewFields
	default:
		selectViewFields = basicViewFields
	}

	roleIDs, err := a.getUserRoleID(ctx)
	if err != nil {
		return nil, err
	}

	var allDepartmentIDs []int

	rdObj, err := a.config.db.RoleDepartments.Query().
		Select(
			roledepartments.FieldDepartmentID,
			roledepartments.FieldRoleID,
		).
		Where(
			roledepartments.RoleIDIn(roleIDs...),
		).All(ctx)
	if err != nil {
		return nil, err
	}

	for _, v := range rdObj {
		allDepartmentIDs = append(allDepartmentIDs, v.DepartmentID)
	}

	// TODO; 先简单提取部门 ID
	if req.GetFilter() != "" {
		departmentID, ok := a.getDepartmentID(req.GetFilter())
		if ok {
			// 判断该部门 ID 是否在 allIDs 中
			hasAllowDepartment := false
			for _, v := range allDepartmentIDs {
				if v == departmentID {
					hasAllowDepartment = true
					break
				}
			}
			if !hasAllowDepartment {
				return result, errs.PermissionDenied(ctx).WithMessage("you are not allowed to view this department")
			}

			// 重新获取所有子部门
			allDepartmentIDs, err = a.getAllSubDeptIDs(ctx, departmentID)
			if err != nil {
				return nil, err
			}
		}
	}

	// 查找用户并实现分页
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	var lastID int
	if req.GetPageToken() != "" {
		data, err := base64.StdEncoding.DecodeString(req.GetPageToken())
		if err != nil {
			return nil, fmt.Errorf("invalid page_token: %w", err)
		}
		if err := json.Unmarshal(data, &lastID); err != nil {
			return nil, fmt.Errorf("invalid page_token format: %w", err)
		}
	}

	allUserIDs := make([]int, 0)

	dps, err := a.config.db.DepartmentMembers.Query().
		Select(
			departmentmembers.FieldUserID,
		).Where(
		departmentmembers.DepartmentIDIn(allDepartmentIDs...),
	).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, v := range dps {
		allUserIDs = append(allUserIDs, v.UserID)
	}

	userQuery := a.config.db.Users.Query()
	userQuery = userQuery.Where(users.IDIn(allUserIDs...))
	if !req.GetShowDeleted() {
		userQuery = userQuery.Where(users.DeletedAtIsNil())
	}

	// OrderBy
	if req.GetOrderBy() != "" {
		switch req.GetOrderBy() {
		case "create_time desc":
			userQuery = userQuery.Order(lion.Desc(users.FieldCreatedAt))
		case "create_time asc":
			userQuery = userQuery.Order(lion.Asc(users.FieldCreatedAt))
		case "nickname asc":
			userQuery = userQuery.Order(lion.Asc(users.FieldNickname))
		case "nickname desc":
			userQuery = userQuery.Order(lion.Desc(users.FieldNickname))
		default:
			// 默认按 ID 升序
			userQuery = userQuery.Order(lion.Desc(users.FieldID))
		}
	} else {
		userQuery = userQuery.Order(lion.Desc(users.FieldID))
	}

	totalSize, err := userQuery.Count(ctx)
	if err != nil {
		return nil, err
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListUsersRequest_Offset:
		// Offset 分页
		userQuery = userQuery.Offset(int(p.Offset))
	case *adminv1.ListUsersRequest_PageToken:
		// Cursor 分页
		if lastID > 0 {
			userQuery = userQuery.Where(users.IDGT(lastID))
		}
	}

	userQuery = userQuery.Limit(pageSize)

	searchUsers, err := userQuery.Select(selectViewFields...).All(ctx)
	if err != nil {
		return nil, err
	}

	// --- 构造 next_page_token ---
	var nextPageToken string
	if len(searchUsers) == pageSize {
		last := searchUsers[len(searchUsers)-1].ID
		tokenData, _ := json.Marshal(last)
		nextPageToken = base64.StdEncoding.EncodeToString(tokenData)
	}

	result.NextPageToken = nextPageToken
	result.TotalSize = int32(totalSize)

	for _, user := range searchUsers {
		realname, _ := crypto.DecryptAES(a.config.aesKey, user.RealnameEncrypted)
		idcard, _ := crypto.DecryptAES(a.config.aesKey, user.NationalIDEncrypted)
		email, _ := crypto.DecryptAES(a.config.aesKey, user.EmailEncrypted)
		phoneNumberByte, _ := crypto.DecryptAES(a.config.aesKey, user.PhoneNumberEncrypted)
		// address, _ := crypto.DecryptAES(a.config.aesKey, user.AddressEncrypted)

		var phoneNumber adminv1.PhoneNumber
		_ = proto.Unmarshal(phoneNumberByte, &phoneNumber)

		var birthday *timestamppb.Timestamp
		if user.Birthdate != nil {
			birthday = timestamppb.New(*user.Birthdate)
		}
		result.Users = append(result.Users, &adminv1.User{
			Id:                  int64(user.ID),
			Username:            user.Username,
			Status:              adminv1.User_Status(user.Status),
			Realname:            string(realname),
			NationalId:          string(idcard),
			Nickname:            user.Nickname,
			Profile:             user.Profile,
			Picture:             user.Picture,
			Website:             user.Website,
			Email:               string(email),
			EmailVerified:       user.EmailVerified,
			Gender:              adminv1.User_Gender(user.Gender),
			Birthday:            birthday,
			Zoneinfo:            user.Zoneinfo,
			Locale:              user.Locale,
			PhoneNumber:         &phoneNumber,
			PhoneNumberVerified: user.PhoneNumberVerified,
			CreatedAt:           timestamppb.New(user.CreatedAt),
			UpdatedAt:           timestamppb.New(user.UpdatedAt),
			// Address:             address,
		})
	}

	return result, nil
}
*/

// UpdateUser 更新用户信息
func (a *KnownAdminAPI) UpdateUser(ctx context.Context, req *adminv1.UpdateUserRequest) (*adminv1.User, error) {
	operatorID, err := a.requireUserManagePermission(ctx, permissionUsersUpdate)
	if err != nil {
		return nil, err
	}
	if req == nil || req.User == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body user is nil")
	}
	if req.User.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("user.id is invalid")
	}
	if req.UpdateMask == nil || len(req.UpdateMask.Paths) == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("update_mask is empty")
	}
	maskPaths := make(map[string]bool, len(req.UpdateMask.Paths))
	for _, path := range req.UpdateMask.Paths {
		if isServerManagedUserField(path) {
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("server-managed update_mask path: %s", path))
		}
		maskPaths[path] = true
	}

	x := a.config.db.Users.Update()
	x.SetUpdatedBy(operatorID)

	// 联系方式发生变更但本次未显式指定验证状态时，验证状态失效，需重置为未验证，
	// 避免新的邮箱/手机号继承旧地址的已验证标记。
	if maskPaths["email"] && !maskPaths["email_verified"] {
		x.SetEmailVerified(false)
	}
	if !maskPaths["phone_number_verified"] &&
		(maskPaths["phone_number"] || maskPaths["phone_number.country_code"] || maskPaths["phone_number.national_number"]) {
		x.SetPhoneNumberVerified(false)
	}

	for _, path := range req.UpdateMask.Paths {
		switch path {
		case "username":
			x.SetUsername(req.User.GetUsername())
		case "nickname":
			x.SetNickname(req.User.GetNickname())
		case "profile":
			x.SetProfile(req.User.GetProfile())
		case "picture":
			x.SetPicture(req.User.GetPicture())
		case "website":
			x.SetWebsite(req.User.GetWebsite())
		case "timezone":
			value, err := normalizeUserTimezone(req.User.GetTimezone())
			if err != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
			}
			x.SetTimezone(value)
		case "locale":
			value, err := normalizeUserLocale(req.User.GetLocale())
			if err != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
			}
			x.SetLocale(value)
		case users.FieldUserType, "type":
			x.SetUserType(int(req.User.GetType()))
		case users.FieldUserStatus, "status":
			x.SetUserStatus(int(req.User.GetStatus()))

		case "gender":
			if !isSupportedGender(req.User.GetGender()) {
				return nil, errs.InvalidArgument(ctx).WithMessage("gender is out of supported range")
			}
			x.SetGender(int(req.User.GetGender()))
		case "realname":
			encBody, err := crypto.EncryptAES(a.config.aesKey, []byte(req.User.GetRealname()))
			if err != nil {
				return nil, err
			}
			x.SetRealnameEncrypted(encBody)
		case "national_id":
			encBody, err := crypto.EncryptAES(a.config.aesKey, []byte(req.User.GetNationalId()))
			if err != nil {
				return nil, err
			}
			x.SetNationalIDEncrypted(encBody)
			x.SetNationalIDHash(crypto.SHA256([]byte(req.User.GetNationalId())))
		case users.FieldBirthdate, "birthday":
			if req.User.GetBirthday() == nil {
				return nil, errs.InvalidArgument(ctx).WithMessage("birthday is nil")
			}
			x.SetBirthdate(req.User.GetBirthday().AsTime())

		case "email":
			if strings.TrimSpace(req.User.GetEmail()) == "" {
				x.ClearEmailEncrypted()
				x.ClearEmailHash()
				x.SetEmailVerified(false)
				continue
			}
			identifier, err := canonicalizeEmailIdentifier(req.User.GetEmail())
			if err != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage("invalid email format")
			}
			encBody, err := crypto.EncryptAES(a.config.aesKey, []byte(identifier.StoredValue))
			if err != nil {
				return nil, err
			}
			x.SetEmailEncrypted(encBody)
			x.SetEmailHash(identifier.Hash)
		case "email_verified":
			x.SetEmailVerified(req.User.GetEmailVerified())
		case "phone_number", "phone_number.country_code", "phone_number.national_number":
			if phoneNumberComplete(req.User.GetPhoneNumber()) {
				identifier, err := canonicalizePhoneNumberIdentifier(req.User.GetPhoneNumber())
				if err != nil {
					return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
				}
				rawBody, err := proto.Marshal(req.User.GetPhoneNumber())
				if err != nil {
					return nil, errs.InvalidArgument(ctx).WithMessage("invalid phone_number format")
				}
				encBody, err := crypto.EncryptAES(a.config.aesKey, rawBody)
				if err != nil {
					return nil, err
				}
				x.SetPhoneNumberEncrypted(encBody)
				x.SetPhoneNumberHash(identifier.Hash)
			} else {
				x.ClearPhoneNumberEncrypted()
				x.ClearPhoneNumberHash()
			}
		case "phone_number_verified":
			x.SetPhoneNumberVerified(req.User.GetPhoneNumberVerified())
		case "address", "address.country", "address.postal_code", "address.region", "address.locality", "address.street_address":
			rawBody, err := proto.Marshal(req.User.GetAddress())
			if err != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage("invalid address format")
			}
			encBody, err := crypto.EncryptAES(a.config.aesKey, rawBody)
			if err != nil {
				return nil, err
			}
			x.SetAddressEncrypted(encBody)
		case users.FieldMetadata:
			x.SetMetadata(req.User.GetMetadata())
		default:
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("unsupported update_mask path: %s", path))
		}
	}

	affected, err := x.Where(users.IDEQ(int(req.User.GetId())), users.DeletedAtIsNil()).Save(ctx)
	if err != nil {
		return nil, err
	}
	if affected == 0 {
		return nil, errs.NotFound(ctx).WithMessage("user not found")
	}

	row, err := a.config.db.Users.Query().
		Where(users.IDEQ(int(req.User.GetId())), users.DeletedAtIsNil()).
		Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("user not found").Err()
		}
		return nil, err
	}

	return a.toAdminUser(ctx, row, true)
}

// GetUser 获取用户详情
func (a *KnownAdminAPI) GetUser(ctx context.Context, req *adminv1.GetUserRequest) (*adminv1.User, error) {
	if _, err := a.requireUserManagePermission(ctx, permissionUsersGet); err != nil {
		return nil, err
	}
	if _, err := a.requireUserManagePermission(ctx, permissionUsersSensitiveGet); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request is nil")
	}
	if req.GetId() <= 0 && req.GetUsername() == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("id or username is required")
	}

	var selectViewFields []string

	basicViewFields := []string{
		users.FieldID,
		users.FieldUsername,
		users.FieldUserType,
		users.FieldUserStatus,
		users.FieldNickname,
		users.FieldProfile,
		users.FieldPicture,
		users.FieldWebsite,
		users.FieldTimezone,
		users.FieldLocale,
		users.FieldCreatedBy,
		users.FieldUpdatedBy,
		users.FieldMetadata,
		users.FieldCreatedAt,
		users.FieldUpdatedAt,
		users.FieldDeletedAt,
	}

	fullViewFields := append(basicViewFields, []string{
		users.FieldRealnameEncrypted,
		users.FieldNationalIDEncrypted,
		users.FieldEmailEncrypted,
		users.FieldEmailVerified,
		users.FieldGender,
		users.FieldBirthdate,
		users.FieldPhoneNumberEncrypted,
		users.FieldPhoneNumberVerified,
		users.FieldAddressEncrypted,
		users.FieldDescription,
	}...)

	selectViewFields = fullViewFields

	userQuery := a.config.db.Users.Query()
	if req.GetId() > 0 {
		userQuery = userQuery.Where(users.IDEQ(int(req.GetId())))
	} else {
		userQuery = userQuery.Where(users.UsernameEQ(req.GetUsername()))
	}
	row, err := userQuery.Select(selectViewFields...).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("user not found").Err()
		}
		return nil, err
	}

	return a.toAdminUser(ctx, row, true)
}

// UpdateUserPassword 修改用户密码
func (a *KnownAdminAPI) UpdateUserPassword(ctx context.Context, req *adminv1.UpdateUserPasswordRequest) (*adminv1.UpdateUserPasswordResponse, error) {
	operatorID, err := a.requireUserManagePermission(ctx, permissionUsersPasswordReset)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request is nil")
	}
	if req.GetUserId() <= 0 && req.GetUsername() == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("user_id or username is required")
	}
	if req.GetNewPasswordHash() == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("new_password_hash is empty")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	targetUserID := int(req.GetUserId())
	if targetUserID <= 0 {
		targetUser, err := db.Users.Query().
			Select(users.FieldID).
			Where(users.UsernameEQ(req.GetUsername()), users.UserStatusEQ(int(adminv1.User_ACTIVE)), users.DeletedAtIsNil()).
			Only(ctx)
		if err != nil {
			if lion.IsNotFound(err) {
				return nil, errs.NotFound(ctx).WithMessage("user not found").Err()
			}
			return nil, err
		}
		targetUserID = targetUser.ID
	}
	active, err := db.Users.Query().
		Where(users.IDEQ(targetUserID), users.UserStatusEQ(int(adminv1.User_ACTIVE)), users.DeletedAtIsNil()).
		Exist(ctx)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, errs.NotFound(ctx).WithMessage("user not found")
	}

	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	active, err = tx.Users.Query().
		Where(users.IDEQ(targetUserID), users.UserStatusEQ(int(adminv1.User_ACTIVE)), users.DeletedAtIsNil()).
		Exist(ctx)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, errs.NotFound(ctx).WithMessage("user not found")
	}

	provider, err := tx.AuthProviders.Query().
		Select(
			authproviders.FieldCode,
		).
		Where(authproviders.ProviderTypeEQ(int(adminv1.AuthProvider_LOCAL.Number()))).
		WithLionUserIdentities(func(q *lion.UserIdentitiesQuery) {
			q.Select(
				useridentities.FieldID,
				useridentities.FieldUserID,
				useridentities.FieldProviderID,
				useridentities.FieldProviderUserID,
				useridentities.FieldPasswordHash,
			).Where(
				useridentities.UserIDEQ(targetUserID),
			)
		}).
		Only(ctx)
	if err != nil {
		return nil, err
	}

	if len(provider.Edges.LionUserIdentities) > 0 {
		currentIdentity := provider.Edges.LionUserIdentities[0]
		if operatorID == int64(targetUserID) && req.GetOldPasswordHash() == "" {
			return nil, errs.InvalidArgument(ctx).WithMessage("old_password_hash is required for self password update")
		}
		if req.GetOldPasswordHash() != "" {
			if err := crypto.BcryptCompare(currentIdentity.PasswordHash, req.GetOldPasswordHash()); err != nil {
				return nil, errs.PermissionDenied(ctx).WithMessage("old_password_hash is incorrect").Err()
			}
		}
	}

	newPasswordHash := crypto.BcryptHashMust(req.GetNewPasswordHash())
	if newPasswordHash == "" {
		return nil, errs.Internal(ctx).WithMessage("new password hash encrypt failed").Err()
	}

	// 不存在则新建
	if len(provider.Edges.LionUserIdentities) == 0 {
		if _, err := tx.UserIdentities.Create().
			SetUserID(targetUserID).
			SetProviderID(provider.ID).
			SetProviderUserID(strconv.Itoa(targetUserID)).
			SetPasswordChangedAt(time.Now()).
			SetPasswordHash(newPasswordHash).Save(ctx); err != nil {
			return nil, err
		}
	} else {
		if _, err := tx.UserIdentities.Update().
			SetPasswordChangedAt(time.Now()).
			SetPasswordHash(newPasswordHash).
			Where(
				useridentities.UserIDEQ(targetUserID),
				useridentities.ProviderIDEQ(provider.ID),
			).Save(ctx); err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &adminv1.UpdateUserPasswordResponse{}, nil
}

func (a *KnownAdminAPI) getDepartmentID(filter string) (int, bool) {
	// 匹配形如 department_id==12 或 department_id == 12
	re := regexp.MustCompile(`department_id\s*==\s*(\d+)`)
	matches := re.FindStringSubmatch(filter)
	if len(matches) == 2 {
		val, err := strconv.Atoi(matches[1])
		if err != nil {
			return 0, false
		}
		return val, true
	}
	return 0, false
}
