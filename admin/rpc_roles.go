package admin

import (
	"context"
	"strconv"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion/grouproles"
	"github.com/grpc-kit/pkg/lion/roledepartments"
	"github.com/grpc-kit/pkg/lion/rolepermissions"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/userroles"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ListRoles 创建用户
func (a *KnownAdminAPI) ListRoles(ctx context.Context, req *adminv1.ListRolesRequest) (*adminv1.ListRolesResponse, error) {
	result := &adminv1.ListRolesResponse{}

	rl, err := a.config.db.Roles.Query().
		Select(roles.FieldID, roles.FieldName, roles.FieldDescription).
		All(ctx)
	if err != nil {
		return nil, err
	}

	for _, r := range rl {
		result.Roles = append(result.Roles, &adminv1.Role{
			Id:          int32(r.ID),
			Name:        r.Name,
			Description: r.Description,
		})
	}

	return result, nil
}

// ListRoleUsers 获取角色用户列表
func (a *KnownAdminAPI) ListRoleUsers(ctx context.Context, req *adminv1.ListRoleUsersRequest) (*adminv1.ListRoleUsersResponse, error) {
	result := &adminv1.ListRoleUsersResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	roleID, err := strconv.Atoi(req.Parent)
	if err != nil {
		return nil, err
	}

	uidObjs, err := db.UserRoles.Query().Select(
		userroles.FieldUserID,
	).Where(
		userroles.RoleIDEQ(roleID),
	).All(ctx)

	if err != nil {
		return nil, err
	}

	uidInts := make([]int, len(uidObjs))
	for i, uidObj := range uidObjs {
		uidInts[i] = int(uidObj.UserID)
	}

	userObjs, err := db.Users.Query().Select(
		users.FieldID,
		users.FieldUsername,
		users.FieldUserStatus,
		users.FieldNickname,
		users.FieldProfile,
		users.FieldPicture,
		users.FieldWebsite,
		users.FieldTimezone,
		users.FieldLocale,
	).Where(
		users.IDIn(uidInts...),
	).All(ctx)
	if err != nil {
		return nil, err
	}

	for _, user := range userObjs {
		result.Users = append(result.Users, &adminv1.User{
			Id:       int64(user.ID),
			Username: user.Username,
			Status:   adminv1.User_Status(user.UserStatus),
			Nickname: user.Nickname,
			Profile:  user.Profile,
			Picture:  user.Picture,
			Website:  user.Website,
			Timezone: user.Timezone,
			Locale:   user.Locale,
		})
	}

	return result, nil
}

// DeleteRoleUser 删除角色用户
func (a *KnownAdminAPI) DeleteRoleUser(ctx context.Context, req *adminv1.DeleteRoleUserRequest) (*emptypb.Empty, error) {
	empty := &emptypb.Empty{}

	roleID, err := strconv.Atoi(req.Parent)
	if err != nil {
		return empty, err
	}

	db, err := a.GetLionClient()
	if err != nil {
		return empty, err
	}

	_, err = db.UserRoles.Delete().
		Where(
			userroles.RoleID(roleID),
			userroles.UserIDEQ(int(req.UserId)),
		).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return empty, nil
}

// CreateRole 创建角色
func (a *KnownAdminAPI) CreateRole(ctx context.Context, req *adminv1.CreateRoleRequest) (*adminv1.Role, error) {
	result := &adminv1.Role{}

	if req.Role == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body role is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	role, err := db.Roles.Create().
		SetName(req.Role.Name).
		SetI18nName(req.Role.I18NName).
		SetDescription(req.Role.Description).
		SetOrderWeight(int(req.Role.OrderWeight)).
		Save(ctx)
	if err != nil {
		return result, err
	}

	result = &adminv1.Role{
		Id:          int32(role.ID),
		Name:        role.Name,
		I18NName:    role.I18nName,
		Description: role.Description,
		OrderWeight: int32(role.OrderWeight),
	}

	return result, nil
}

// DeleteRole 删除角色
func (a *KnownAdminAPI) DeleteRole(ctx context.Context, req *adminv1.DeleteRoleRequest) (*emptypb.Empty, error) {
	// 涉及的几个角色表均不能存在关联

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	if db.GroupRoles.Query().Where(grouproles.RoleIDEQ(int(req.Id))).CountX(ctx) > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role has group")
	}

	if db.RoleDepartments.Query().Where(roledepartments.RoleIDEQ(int(req.Id))).CountX(ctx) > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role has department")
	}

	if db.RolePermissions.Query().Where(rolepermissions.RoleIDEQ(int(req.Id))).CountX(ctx) > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role has permission")
	}

	if db.RolePermissions.Query().Where(rolepermissions.RoleIDEQ(int(req.Id))).CountX(ctx) > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role has resource")
	}

	if db.UserRoles.Query().Where(userroles.RoleIDEQ(int(req.Id))).CountX(ctx) > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role has user")
	}

	_, err = db.Roles.Delete().Where(roles.ID(int(req.Id))).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// UpdateRole 更新角色
func (a *KnownAdminAPI) UpdateRole(ctx context.Context, req *adminv1.UpdateRoleRequest) (*adminv1.Role, error) {
	result := &adminv1.Role{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	if req.UpdateMask != nil && len(req.UpdateMask.Paths) != 0 {
		x := db.Roles.Update()

		for _, path := range req.UpdateMask.Paths {
			switch path {
			case roles.FieldName:
				x.SetName(req.Role.Name)
				/*
					case roles.FieldI18nName + ".zh_cn":
						if req.Role.I18NName != nil {
							if req.Role.I18NName.ZhCn != "" {
								x.SetI18nName(I18NNameJSON(req.Role.I18NName))
							}
						}
				*/
			case roles.FieldOrderWeight:
				x.SetOrderWeight(int(req.Role.OrderWeight))
			case roles.FieldDescription:
				x.SetDescription(req.Role.Description)
			}
		}

		save, err := x.Where(roles.ID(int(req.Role.Id))).Save(ctx)
		if err != nil {
			return nil, err
		}

		a.logger.Infof("update role save: %v, req id: %v", save, req.Role.Id)

		q, err := db.Roles.Query().Select(
			roles.FieldID,
			roles.FieldName,
			roles.FieldI18nName,
			roles.FieldRoleType,
			roles.FieldRoleStatus,
			roles.FieldOrderWeight,
			roles.FieldDescription,
		).Where(
			roles.ID(int(req.Role.Id)),
		).Only(ctx)
		if err != nil {
			return nil, err
		}

		result = &adminv1.Role{
			Id:          int32(q.ID),
			Name:        q.Name,
			I18NName:    q.I18nName,
			Description: q.Description,
			OrderWeight: int32(q.OrderWeight),
		}
	}

	return result, nil
}

// AssignRoleToUser 角色分配用户
func (a *KnownAdminAPI) AssignRoleToUser(ctx context.Context, req *adminv1.AssignRoleToUserRequest) (*emptypb.Empty, error) {
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	if len(req.Users) == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("users is empty")
	}

	for _, userID := range req.Users {
		_, _ = db.UserRoles.Create().SetRoleID(int(req.RoleId)).SetUserID(int(userID.Id)).Save(ctx)
	}

	return &emptypb.Empty{}, nil
}
