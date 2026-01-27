package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/grouproles"
	"github.com/grpc-kit/pkg/lion/roledatascopes"
	"github.com/grpc-kit/pkg/lion/rolepermissions"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/userroles"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// getAllChildRoleIDs 递归获取所有子角色ID
func (a *KnownAdminAPI) getAllChildRoleIDs(ctx context.Context, db *lion.Client, parentIDs []int) ([]int, error) {
	if len(parentIDs) == 0 {
		return []int{}, nil
	}

	// 查询所有子角色
	childRoles, err := db.Roles.Query().
		Select(roles.FieldID, roles.FieldParentID).
		Where(roles.ParentIDIn(parentIDs...)).
		All(ctx)
	if err != nil {
		return nil, err
	}

	if len(childRoles) == 0 {
		return []int{}, nil
	}

	// 收集子角色ID
	childIDs := make([]int, 0, len(childRoles))
	for _, child := range childRoles {
		childIDs = append(childIDs, child.ID)
	}

	// 递归获取子角色的子角色
	grandChildIDs, err := a.getAllChildRoleIDs(ctx, db, childIDs)
	if err != nil {
		return nil, err
	}

	// 合并所有子角色ID
	allChildIDs := append(childIDs, grandChildIDs...)
	return allChildIDs, nil
}

// checkRolePermission 检查用户是否有权限操作指定角色
// 返回 true 表示用户拥有该角色或其子角色，可以操作
func (a *KnownAdminAPI) checkRolePermission(ctx context.Context, db *lion.Client, roleID int) error {
	// 获取当前用户的角色ID列表
	userRoleIDs, err := a.getUserRoleID(ctx)
	if err != nil {
		return err
	}

	if len(userRoleIDs) == 0 {
		return errs.PermissionDenied(ctx).WithMessage("user has no roles")
	}

	// 检查目标角色是否就是用户拥有的角色之一
	for _, userRoleID := range userRoleIDs {
		if userRoleID == roleID {
			return nil
		}
	}

	// 递归获取所有子角色ID
	allChildRoleIDs, err := a.getAllChildRoleIDs(ctx, db, userRoleIDs)
	if err != nil {
		return err
	}

	// 检查目标角色是否是用户角色的子角色
	for _, childRoleID := range allChildRoleIDs {
		if childRoleID == roleID {
			return nil
		}
	}

	// 没有权限
	return errs.PermissionDenied(ctx).WithMessage("user does not have permission to access this role")
}

// checkParentRolePermission 检查用户是否有权限将新角色创建为指定父角色的子角色
// 如果 parentID 为 0，表示创建根角色，需要检查用户是否有根角色权限
func (a *KnownAdminAPI) checkParentRolePermission(ctx context.Context, db *lion.Client, parentID int32) error {
	if parentID == 0 {
		// 创建根角色，需要检查用户是否有根角色
		userRoleIDs, err := a.getUserRoleID(ctx)
		if err != nil {
			return err
		}

		if len(userRoleIDs) == 0 {
			return errs.PermissionDenied(ctx).WithMessage("user has no roles")
		}

		// 检查用户是否有根角色（parent_id = 0）
		userRootRoles, err := db.Roles.Query().
			Select(roles.FieldID, roles.FieldParentID).
			Where(
				roles.IDIn(userRoleIDs...),
				roles.ParentIDEQ(0),
			).
			All(ctx)
		if err != nil {
			return err
		}

		if len(userRootRoles) == 0 {
			return errs.PermissionDenied(ctx).WithMessage("user does not have root role permission to create root role")
		}

		return nil
	}

	// 检查用户是否有权限操作父角色
	return a.checkRolePermission(ctx, db, int(parentID))
}

// ListRoles 获取角色列表，默认返回树状结构
// 仅返回当前用户拥有的角色及其所有子角色
func (a *KnownAdminAPI) ListRoles(ctx context.Context, req *adminv1.ListRolesRequest) (*adminv1.ListRolesResponse, error) {
	result := &adminv1.ListRolesResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 获取当前用户的角色ID列表
	userRoleIDs, err := a.getUserRoleID(ctx)
	if err != nil {
		return nil, err
	}

	if len(userRoleIDs) == 0 {
		// 用户没有任何角色，返回空列表
		result.Roles = []*adminv1.Role{}
		result.TotalSize = 0
		return result, nil
	}

	// 递归获取所有子角色ID
	allChildRoleIDs, err := a.getAllChildRoleIDs(ctx, db, userRoleIDs)
	if err != nil {
		return nil, err
	}

	// 合并用户角色ID和所有子角色ID
	allowedRoleIDs := make(map[int]bool)
	for _, id := range userRoleIDs {
		allowedRoleIDs[id] = true
	}
	for _, id := range allChildRoleIDs {
		allowedRoleIDs[id] = true
	}

	// 转换为切片用于查询
	allowedRoleIDsSlice := make([]int, 0, len(allowedRoleIDs))
	for id := range allowedRoleIDs {
		allowedRoleIDsSlice = append(allowedRoleIDsSlice, id)
	}

	// 添加 parent_id 字段到查询字段列表
	defaultSelect := []string{
		roles.FieldID,
		roles.FieldParentID,
		roles.FieldCode,
		roles.FieldDisplayName,
		roles.FieldRoleType,
		roles.FieldRoleStatus,
		roles.FieldSortOrder,
		roles.FieldDescription,
		roles.FieldCreatedAt,
		roles.FieldUpdatedAt,
	}

	roleQuery := db.Roles.Query().
		Where(roles.IDIn(allowedRoleIDsSlice...))

	// 查找用户并实现分页
	pageSize := GetPageSize(ctx, req.PageSize)

	// OrderBy
	if req.GetOrderBy() != "" {
		switch req.GetOrderBy() {
		case "create_time desc":
			roleQuery = roleQuery.Order(lion.Desc(roles.FieldCreatedAt))
		case "create_time asc":
			roleQuery = roleQuery.Order(lion.Asc(roles.FieldCreatedAt))
		default:
			roleQuery = roleQuery.Order(lion.Desc(roles.FieldID))
		}
	} else {
		// 默认按 sort_order 升序，然后按 ID 升序
		roleQuery = roleQuery.Order(lion.Asc(roles.FieldSortOrder), lion.Asc(roles.FieldID))
	}

	totalSize, err := roleQuery.Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	switch p := req.GetPagination().(type) {
	case *adminv1.ListRolesRequest_Offset:
		// Offset 分页
		roleQuery = roleQuery.Offset(int(p.Offset))
	case *adminv1.ListRolesRequest_PageToken:
		// TODO; Cursor 分页
	}

	roleQuery = roleQuery.Limit(int(pageSize))

	rl, err := roleQuery.Select(defaultSelect...).All(ctx)
	if err != nil {
		return nil, err
	}

	// 构建角色映射和树状结构
	roleMap := make(map[int32]*adminv1.Role)
	var roots []*adminv1.Role

	// 首先将所有角色转换为 protobuf 格式并存入 map
	for _, r := range rl {
		role := &adminv1.Role{
			Id:          int32(r.ID),
			ParentId:    int32(r.ParentID),
			Code:        r.Code,
			DisplayName: r.DisplayName,
			Type:        adminv1.Role_Type(r.RoleType),
			Status:      adminv1.Role_Status(r.RoleStatus),
			SortOrder:   int32(r.SortOrder),
			Description: r.Description,
			CreatedAt:   timestamppb.New(r.CreatedAt),
			UpdatedAt:   timestamppb.New(r.UpdatedAt),
			Children:    make([]*adminv1.Role, 0),
		}

		roleMap[int32(r.ID)] = role
	}

	// 构建父子关系
	for _, role := range roleMap {
		if role.ParentId != 0 {
			if parent, ok := roleMap[role.ParentId]; ok {
				parent.Children = append(parent.Children, role)
			} else {
				// 父节点不在当前查询结果中，作为根节点处理
				roots = append(roots, role)
			}
		} else {
			// parent_id 为 0，是根节点
			roots = append(roots, role)
		}
	}

	// 对根节点排序
	sort.Slice(roots, func(i, j int) bool {
		if roots[i].SortOrder != roots[j].SortOrder {
			return roots[i].SortOrder < roots[j].SortOrder
		}
		return roots[i].Id < roots[j].Id
	})

	// 递归排序子节点
	a.sortRoleChildren(roots)

	result.Roles = roots

	return result, nil
}


// sortRoleChildren 递归排序角色的子节点
func (a *KnownAdminAPI) sortRoleChildren(roles []*adminv1.Role) {
	for _, role := range roles {
		if len(role.Children) > 0 {
			sort.Slice(role.Children, func(i, j int) bool {
				if role.Children[i].SortOrder != role.Children[j].SortOrder {
					return role.Children[i].SortOrder < role.Children[j].SortOrder
				}
				return role.Children[i].Id < role.Children[j].Id
			})
			// 递归排序子节点的子节点
			a.sortRoleChildren(role.Children)
		}
	}
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

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, roleID); err != nil {
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

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, roleID); err != nil {
		return nil, err
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

	// 检查用户是否有权限创建该父角色的子角色
	if err := a.checkParentRolePermission(ctx, db, req.Role.ParentId); err != nil {
		return nil, err
	}

	createBuilder := db.Roles.Create().
		SetCode(req.Role.Code).
		SetDisplayName(req.Role.DisplayName).
		SetDescription(req.Role.Description).
		SetSortOrder(int(req.Role.SortOrder))

	// 设置 parent_id（如果提供）
	if req.Role.ParentId > 0 {
		createBuilder.SetParentID(int(req.Role.ParentId))
	}

	// 获取创建者用户 ID
	userID, _ := GetUserID(ctx)
	if userID > 0 {
		createBuilder.SetCreatedBy(userID).SetUpdatedBy(userID)
	}

	role, err := createBuilder.Save(ctx)
	if err != nil {
		return result, err
	}

	result = &adminv1.Role{
		Id:          int32(role.ID),
		ParentId:    int32(role.ParentID),
		Code:        role.Code,
		DisplayName: role.DisplayName,
		Description: role.Description,
		SortOrder:   int32(role.SortOrder),
		Type:        adminv1.Role_Type(role.RoleType),
		Status:      adminv1.Role_Status(role.RoleStatus),
		CreatedBy:   role.CreatedBy,
		UpdatedBy:   role.UpdatedBy,
		CreatedAt:   timestamppb.New(role.CreatedAt),
		UpdatedAt:   timestamppb.New(role.UpdatedAt),
		Children:   make([]*adminv1.Role, 0),
	}

	return result, nil
}

// GetRole 获取角色详情
func (a *KnownAdminAPI) GetRole(ctx context.Context, req *adminv1.GetRoleRequest) (*adminv1.Role, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 查询角色信息
	role, err := db.Roles.Query().Select(
		roles.FieldID,
		roles.FieldParentID,
		roles.FieldCode,
		roles.FieldDisplayName,
		roles.FieldRoleType,
		roles.FieldRoleStatus,
		roles.FieldSortOrder,
		roles.FieldDescription,
		roles.FieldCreatedBy,
		roles.FieldUpdatedBy,
		roles.FieldCreatedAt,
		roles.FieldUpdatedAt,
	).Where(
		roles.ID(int(req.Id)),
	).Only(ctx)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role not found")
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, role.ID); err != nil {
		return nil, err
	}

	result := &adminv1.Role{
		Id:          int32(role.ID),
		ParentId:    int32(role.ParentID),
		Code:        role.Code,
		DisplayName: role.DisplayName,
		Description: role.Description,
		SortOrder:   int32(role.SortOrder),
		Type:        adminv1.Role_Type(role.RoleType),
		Status:      adminv1.Role_Status(role.RoleStatus),
		CreatedBy:   role.CreatedBy,
		UpdatedBy:   role.UpdatedBy,
		CreatedAt:   timestamppb.New(role.CreatedAt),
		UpdatedAt:   timestamppb.New(role.UpdatedAt),
		Children:    make([]*adminv1.Role, 0),
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

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.Id)); err != nil {
		return nil, err
	}

	if db.GroupRoles.Query().Where(grouproles.RoleIDEQ(int(req.Id))).CountX(ctx) > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role has group")
	}

	if db.RoleDataScopes.Query().Where(roledatascopes.RoleIDEQ(int(req.Id))).CountX(ctx) > 0 {
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

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.Role.Id)); err != nil {
		return nil, err
	}

	if req.UpdateMask != nil && len(req.UpdateMask.Paths) != 0 {
		x := db.Roles.Update()

		// 获取更新者用户 ID
		userID, _ := GetUserID(ctx)

		for _, path := range req.UpdateMask.Paths {
			switch path {
			case roles.FieldCode:
				x.SetCode(req.Role.Code)
			case roles.FieldParentID:
				// 更新 parent_id，需要检查新父角色的权限
				if err := a.checkParentRolePermission(ctx, db, req.Role.ParentId); err != nil {
					return nil, err
				}
				x.SetParentID(int(req.Role.ParentId))
			case roles.FieldSortOrder:
				x.SetSortOrder(int(req.Role.SortOrder))
			case roles.FieldDescription:
				x.SetDescription(req.Role.Description)
			case roles.FieldDisplayName:
				x.SetDisplayName(req.Role.DisplayName)
			}
		}

		// 更新 updated_by
		if userID > 0 {
			x.SetUpdatedBy(userID)
		}

		save, err := x.Where(roles.ID(int(req.Role.Id))).Save(ctx)
		if err != nil {
			return nil, err
		}

		a.logger.Infof("update role save: %v, req id: %v", save, req.Role.Id)

		// 查询更新后的角色信息，包含 parent_id
		q, err := db.Roles.Query().Select(
			roles.FieldID,
			roles.FieldParentID,
			roles.FieldCode,
			roles.FieldDisplayName,
			roles.FieldRoleType,
			roles.FieldRoleStatus,
			roles.FieldSortOrder,
			roles.FieldDescription,
			roles.FieldCreatedBy,
			roles.FieldUpdatedBy,
			roles.FieldCreatedAt,
			roles.FieldUpdatedAt,
		).Where(
			roles.ID(int(req.Role.Id)),
		).Only(ctx)
		if err != nil {
			return nil, err
		}

		result = &adminv1.Role{
			Id:          int32(q.ID),
			ParentId:    int32(q.ParentID),
			Code:        q.Code,
			DisplayName: q.DisplayName,
			Description: q.Description,
			SortOrder:   int32(q.SortOrder),
			Type:        adminv1.Role_Type(q.RoleType),
			Status:      adminv1.Role_Status(q.RoleStatus),
			CreatedBy:   q.CreatedBy,
			UpdatedBy:   q.UpdatedBy,
			CreatedAt:   timestamppb.New(q.CreatedAt),
			UpdatedAt:   timestamppb.New(q.UpdatedAt),
			Children:   make([]*adminv1.Role, 0),
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

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.RoleId)); err != nil {
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

// CreateRolePermissions 为角色关联权限
func (a *KnownAdminAPI) CreateRolePermissions(ctx context.Context, req *adminv1.CreateRolePermissionsRequest) (*adminv1.CreateRolePermissionsResponse, error) {
	result := &adminv1.CreateRolePermissionsResponse{}

	if req.RoleId == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("role_id is required")
	}

	if len(req.Permissions) == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("permissions list is empty")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.RoleId)); err != nil {
		return nil, err
	}

	// 获取创建者用户 ID
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	// 检查角色是否存在
	_, err = db.Roles.Get(ctx, int(req.RoleId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role not found")
	}

	// 收集有效的权限 IDs 并验证每个权限是否存在
	permissionIDs := make([]int, 0, len(req.Permissions))
	permissionMap := make(map[int64]*adminv1.Permission)

	for _, perm := range req.Permissions {
		if perm.Id == 0 {
			continue
		}

		// 检查权限是否存在
		dbPermission, err := db.Permissions.Get(ctx, int(perm.Id))
		if err != nil {
			// 如果某个权限不存在，可以选择跳过或返回错误
			// 这里选择跳过不存在的权限
			continue
		}

		permissionIDs = append(permissionIDs, dbPermission.ID)
		// 保存权限信息以便后续返回
		permissionMap[perm.Id] = &adminv1.Permission{
			Id:          int64(dbPermission.ID),
			Code:        dbPermission.Code,
			DisplayName: dbPermission.DisplayName,
			Description: dbPermission.Description,
		}
	}

	if len(permissionIDs) == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("no valid permissions found")
	}

	// 检查是否已存在关联关系，如果存在则跳过
	existingRolePermissions, err := db.RolePermissions.Query().
		Where(
			rolepermissions.RoleIDEQ(int(req.RoleId)),
			rolepermissions.PermissionIDIn(permissionIDs...),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	// 构建已存在的 permission ID 集合
	existingPermissionIDSet := make(map[int]bool)
	for _, rp := range existingRolePermissions {
		existingPermissionIDSet[rp.PermissionID] = true
	}

	// 过滤出需要创建的 permission IDs（排除已存在的）
	permissionsToCreate := make([]int, 0)
	for _, permissionID := range permissionIDs {
		if !existingPermissionIDSet[permissionID] {
			permissionsToCreate = append(permissionsToCreate, permissionID)
		}
	}

	// 批量创建关联关系
	if len(permissionsToCreate) > 0 {
		allRolePermissions := make([]*lion.RolePermissionsCreate, 0, len(permissionsToCreate))

		for _, permissionID := range permissionsToCreate {
			rp := db.RolePermissions.Create().
				SetRoleID(int(req.RoleId)).
				SetPermissionID(permissionID).
				SetCreatedBy(userID).
				SetUpdatedBy(userID)

			allRolePermissions = append(allRolePermissions, rp)
		}

		_, err = db.RolePermissions.CreateBulk(allRolePermissions...).Save(ctx)
		if err != nil {
			return nil, err
		}
	}

	// 返回所有关联的权限（包括已存在的和新创建的）
	for _, perm := range req.Permissions {
		if perm.Id != 0 {
			if p, ok := permissionMap[perm.Id]; ok {
				result.Permissions = append(result.Permissions, p)
			}
		}
	}

	return result, nil
}

// DeleteRolePermission 删除角色下的权限关联
func (a *KnownAdminAPI) DeleteRolePermission(ctx context.Context, req *adminv1.DeleteRolePermissionRequest) (*emptypb.Empty, error) {
	if req.RoleId == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role_id is required")
	}

	if req.PermissionId == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("permission_id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.RoleId)); err != nil {
		return nil, err
	}

	// 检查角色是否存在
	_, err = db.Roles.Get(ctx, int(req.RoleId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role not found")
	}

	// 检查权限是否存在
	_, err = db.Permissions.Get(ctx, int(req.PermissionId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("permission not found")
	}

	// 检查关联关系是否存在
	_, err = db.RolePermissions.Query().
		Where(
			rolepermissions.RoleIDEQ(int(req.RoleId)),
			rolepermissions.PermissionIDEQ(int(req.PermissionId)),
		).
		Only(ctx)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role permission relationship not found")
	}

	// 删除关联关系
	_, err = db.RolePermissions.Delete().
		Where(
			rolepermissions.RoleIDEQ(int(req.RoleId)),
			rolepermissions.PermissionIDEQ(int(req.PermissionId)),
		).
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// ListRolePermissions 列出角色下的所有权限
func (a *KnownAdminAPI) ListRolePermissions(ctx context.Context, req *adminv1.ListRolePermissionsRequest) (*adminv1.ListRolePermissionsResponse, error) {
	result := &adminv1.ListRolePermissionsResponse{}

	if req.RoleId == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("role_id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.RoleId)); err != nil {
		return nil, err
	}

	// 检查角色是否存在
	_, err = db.Roles.Get(ctx, int(req.RoleId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role not found")
	}

	// 查询角色权限关联
	rolePermissionQuery := db.RolePermissions.Query().
		Where(rolepermissions.RoleIDEQ(int(req.RoleId)))

	// 如果 View 为 FULL，需要预加载权限的详细信息（策略和资源）
	if req.View == adminv1.View_FULL {
		rolePermissionQuery = rolePermissionQuery.
			WithLionPermissions(
				func(query *lion.PermissionsQuery) {
					query.WithLionPolicies().
						WithLionPermissionBindings(
							func(query *lion.PermissionBindingsQuery) {
								query.WithLionResourceScopes(
									func(query *lion.ResourceScopesQuery) {
										query.WithLionResources().
											WithLionScopes()
									},
								)
							},
						)
				},
			)
	} else {
		// BASIC 或 STANDARD 视图，只加载基本信息
		rolePermissionQuery = rolePermissionQuery.WithLionPermissions()
	}

	// 计算总数（在应用分页前）
	totalSize, err := rolePermissionQuery.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	// 处理分页
	pageSize := GetPageSize(ctx, req.PageSize)

	// 处理排序
	if req.OrderBy != "" {
		switch req.OrderBy {
		case "create_time desc":
			rolePermissionQuery = rolePermissionQuery.Order(lion.Desc(rolepermissions.FieldCreatedAt))
		case "create_time asc":
			rolePermissionQuery = rolePermissionQuery.Order(lion.Asc(rolepermissions.FieldCreatedAt))
		default:
			rolePermissionQuery = rolePermissionQuery.Order(lion.Desc(rolepermissions.FieldCreatedAt))
		}
	} else {
		// 默认排序
		rolePermissionQuery = rolePermissionQuery.Order(lion.Desc(rolepermissions.FieldCreatedAt))
	}

	var lastID int
	if req.GetPageToken() != "" {
		// Cursor-based 分页
		data, err := base64.StdEncoding.DecodeString(req.GetPageToken())
		if err != nil {
			return nil, fmt.Errorf("invalid page_token: %w", err)
		}
		if err := json.Unmarshal(data, &lastID); err != nil {
			return nil, fmt.Errorf("invalid page_token format: %w", err)
		}
		if lastID > 0 {
			rolePermissionQuery = rolePermissionQuery.Where(rolepermissions.IDGT(lastID))
		}
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListRolePermissionsRequest_Offset:
		// Offset-based 分页
		rolePermissionQuery = rolePermissionQuery.Offset(int(p.Offset))
	case *adminv1.ListRolePermissionsRequest_PageToken:
		// Cursor-based 分页已在上面处理
	}

	// 应用 Limit
	rolePermissionQuery = rolePermissionQuery.Limit(int(pageSize))

	// 执行查询
	rolePermissionList, err := rolePermissionQuery.All(ctx)
	if err != nil {
		return nil, err
	}

	// 转换为响应格式
	for _, rp := range rolePermissionList {
		if rp.Edges.LionPermissions == nil {
			continue
		}

		perm := rp.Edges.LionPermissions
		permission := &adminv1.Permission{
			Id:          int64(perm.ID),
			Code:        perm.Code,
			DisplayName: perm.DisplayName,
			Description: perm.Description,
		}

		// 如果 View 为 FULL，加载策略和资源信息
		if req.View == adminv1.View_FULL {
			// 加载策略信息
			if perm.Edges.LionPolicies != nil {
				policy := perm.Edges.LionPolicies
				permission.Policy = &adminv1.Policy{
					Id:          int32(policy.ID),
					Code:        policy.Code,
					DisplayName: policy.DisplayName,
					Type:        adminv1.Policy_Type(policy.PolicyType),
					Status:      adminv1.Policy_Status(policy.PolicyStatus),
					Value:       policy.Value,
					Description: policy.Description,
				}
			}

			// 加载资源信息（通过 permission_bindings -> resource_scopes -> resources）
			if perm.Edges.LionPermissionBindings != nil {
				resourceMap := make(map[int64]*adminv1.Resource)
				resourceScopesMap := make(map[int64]map[int64]*adminv1.Scope) // resource_id -> scope_id -> scope
				for _, binding := range perm.Edges.LionPermissionBindings {
					if binding.Edges.LionResourceScopes != nil {
						rs := binding.Edges.LionResourceScopes
						resourceID := int64(0)

						// 加载资源
						if rs.Edges.LionResources != nil {
							res := rs.Edges.LionResources
							resourceID = int64(res.ID)
							if _, exists := resourceMap[resourceID]; !exists {
								resourceMap[resourceID] = &adminv1.Resource{
									Id:          int64(res.ID),
									ParentId:    res.ParentID,
									Code:        res.Code,
									DisplayName: res.DisplayName,
									SortOrder:   int32(res.SortOrder),
									Type:        adminv1.Resource_Type(res.ResourceType),
									Status:      adminv1.Resource_Status(res.ResourceStatus),
									Visibility:  adminv1.Resource_Visibility(res.Visibility),
									Locator:     res.Locator,
									Visual:      res.Visual,
									Manifest:    res.Manifest,
									Description: res.Description,
								}
							}
						}

						// 加载作用域
						if rs.Edges.LionScopes != nil && resourceID != 0 {
							s := rs.Edges.LionScopes
							if resourceScopesMap[resourceID] == nil {
								resourceScopesMap[resourceID] = make(map[int64]*adminv1.Scope)
							}
							// 使用 scope ID 作为 key 去重
							if _, exists := resourceScopesMap[resourceID][int64(s.ID)]; !exists {
								resourceScopesMap[resourceID][int64(s.ID)] = &adminv1.Scope{
									Id:          int64(s.ID),
									Code:        s.Code,
									DisplayName: s.DisplayName,
									Type:        adminv1.Scope_Type(s.ScopeType),
								}
							}
						}
					}
				}
				// 将 map 转换为 slice，并添加 scopes
				for resourceID, res := range resourceMap {
					if scopesMap, exists := resourceScopesMap[resourceID]; exists {
						for _, scope := range scopesMap {
							res.Scopes = append(res.Scopes, scope)
						}
					}
					permission.Resources = append(permission.Resources, res)
				}
			}
		}

		result.Permissions = append(result.Permissions, permission)
	}

	// 构造 next_page_token（仅用于 cursor-based 分页）
	switch req.GetPagination().(type) {
	case *adminv1.ListRolePermissionsRequest_PageToken:
		// 只有在使用 cursor-based 分页时才生成 next_page_token
		if len(rolePermissionList) == int(pageSize) && len(rolePermissionList) > 0 {
			last := rolePermissionList[len(rolePermissionList)-1].ID
			tokenData, _ := json.Marshal(last)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}

	return result, nil
}

// CreateRoleDataScopes 为角色关联部门
func (a *KnownAdminAPI) CreateRoleDataScopes(ctx context.Context, req *adminv1.CreateRoleDataScopesRequest) (*adminv1.CreateRoleDataScopesResponse, error) {
	result := &adminv1.CreateRoleDataScopesResponse{}

	if req.RoleId == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("role_id is required")
	}

	if len(req.Departments) == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("departments list is empty")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.RoleId)); err != nil {
		return nil, err
	}

	// 获取创建者用户 ID
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	// 检查角色是否存在
	_, err = db.Roles.Get(ctx, int(req.RoleId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role not found")
	}

	// 收集有效的部门 IDs 并验证每个部门是否存在
	departmentIDs := make([]int, 0, len(req.Departments))
	departmentMap := make(map[int32]*adminv1.Department)

	for _, dept := range req.Departments {
		if dept.Id == 0 {
			continue
		}

		// 检查部门是否存在
		dbDepartment, err := db.Departments.Get(ctx, int(dept.Id))
		if err != nil {
			// 如果某个部门不存在，可以选择跳过或返回错误
			// 这里选择跳过不存在的部门
			continue
		}

		departmentIDs = append(departmentIDs, dbDepartment.ID)
		// 保存部门信息以便后续返回
		departmentMap[dept.Id] = &adminv1.Department{
			Id:          int32(dbDepartment.ID),
			ParentId:    int32(dbDepartment.ParentID),
			Code:        dbDepartment.Code,
			DisplayName: dbDepartment.DisplayName,
			Type:        adminv1.Department_Type(dbDepartment.DepartmentType),
			Status:      adminv1.Department_Status(dbDepartment.DepartmentStatus),
			SortOrder:   int32(dbDepartment.SortOrder),
		}
	}

	if len(departmentIDs) == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("no valid departments found")
	}

	// 检查是否已存在关联关系，如果存在则跳过
	existingRoleDataScopes, err := db.RoleDataScopes.Query().
		Where(
			roledatascopes.RoleIDEQ(int(req.RoleId)),
			roledatascopes.DepartmentIDIn(departmentIDs...),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	// 构建已存在的 department ID 集合
	existingDepartmentIDSet := make(map[int]bool)
	for _, rd := range existingRoleDataScopes {
		existingDepartmentIDSet[rd.DepartmentID] = true
	}

	// 过滤出需要创建的 department IDs（排除已存在的）
	departmentsToCreate := make([]int, 0)
	for _, departmentID := range departmentIDs {
		if !existingDepartmentIDSet[departmentID] {
			departmentsToCreate = append(departmentsToCreate, departmentID)
		}
	}

	// 批量创建关联关系
	if len(departmentsToCreate) > 0 {
		allRoleDataScopes := make([]*lion.RoleDataScopesCreate, 0, len(departmentsToCreate))

		for _, departmentID := range departmentsToCreate {
			rd := db.RoleDataScopes.Create().
				SetRoleID(int(req.RoleId)).
				SetDepartmentID(departmentID).
				SetCreatedBy(userID).
				SetUpdatedBy(userID)

			allRoleDataScopes = append(allRoleDataScopes, rd)
		}

		_, err = db.RoleDataScopes.CreateBulk(allRoleDataScopes...).Save(ctx)
		if err != nil {
			return nil, err
		}
	}

	// 返回所有关联的部门（包括已存在的和新创建的）
	for _, dept := range req.Departments {
		if dept.Id != 0 {
			if d, ok := departmentMap[dept.Id]; ok {
				result.Departments = append(result.Departments, d)
			}
		}
	}

	return result, nil
}

// DeleteRoleDataScopes 删除角色下的数据范围关联
func (a *KnownAdminAPI) DeleteRoleDataScopes(ctx context.Context, req *adminv1.DeleteRoleDataScopesRequest) (*emptypb.Empty, error) {
	if req.RoleId == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role_id is required")
	}

	if req.DepartmentId == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("department_id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.RoleId)); err != nil {
		return nil, err
	}

	// 检查角色是否存在
	_, err = db.Roles.Get(ctx, int(req.RoleId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role not found")
	}

	// 检查部门是否存在
	_, err = db.Departments.Get(ctx, int(req.DepartmentId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("department not found")
	}

	// 检查关联关系是否存在
	_, err = db.RoleDataScopes.Query().
		Where(
			roledatascopes.RoleIDEQ(int(req.RoleId)),
			roledatascopes.DepartmentIDEQ(int(req.DepartmentId)),
		).
		Only(ctx)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role department relationship not found")
	}

	// 删除关联关系
	_, err = db.RoleDataScopes.Delete().
		Where(
			roledatascopes.RoleIDEQ(int(req.RoleId)),
			roledatascopes.DepartmentIDEQ(int(req.DepartmentId)),
		).
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// ListRoleDataScopes 列出角色下的所有部门
func (a *KnownAdminAPI) ListRoleDataScopes(ctx context.Context, req *adminv1.ListRoleDataScopesRequest) (*adminv1.ListRoleDataScopesResponse, error) {
	result := &adminv1.ListRoleDataScopesResponse{}

	if req.RoleId == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("role_id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.RoleId)); err != nil {
		return nil, err
	}

	// 检查角色是否存在
	_, err = db.Roles.Get(ctx, int(req.RoleId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role not found")
	}

	// 查询角色部门关联
	roleDepartmentQuery := db.RoleDataScopes.Query().
		Where(roledatascopes.RoleIDEQ(int(req.RoleId)))

	// 计算总数（在应用分页前）
	totalSize, err := roleDepartmentQuery.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	// 处理分页
	pageSize := GetPageSize(ctx, req.PageSize)

	// 处理排序
	if req.OrderBy != "" {
		switch req.OrderBy {
		case "create_time desc":
			roleDepartmentQuery = roleDepartmentQuery.Order(lion.Desc(roledatascopes.FieldCreatedAt))
		case "create_time asc":
			roleDepartmentQuery = roleDepartmentQuery.Order(lion.Asc(roledatascopes.FieldCreatedAt))
		default:
			roleDepartmentQuery = roleDepartmentQuery.Order(lion.Desc(roledatascopes.FieldCreatedAt))
		}
	} else {
		// 默认排序
		roleDepartmentQuery = roleDepartmentQuery.Order(lion.Desc(roledatascopes.FieldCreatedAt))
	}

	var lastID int
	if req.GetPageToken() != "" {
		// Cursor-based 分页
		data, err := base64.StdEncoding.DecodeString(req.GetPageToken())
		if err != nil {
			return nil, fmt.Errorf("invalid page_token: %w", err)
		}
		if err := json.Unmarshal(data, &lastID); err != nil {
			return nil, fmt.Errorf("invalid page_token format: %w", err)
		}
		if lastID > 0 {
			roleDepartmentQuery = roleDepartmentQuery.Where(roledatascopes.IDGT(lastID))
		}
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListRoleDataScopesRequest_Offset:
		// Offset-based 分页
		roleDepartmentQuery = roleDepartmentQuery.Offset(int(p.Offset))
	case *adminv1.ListRoleDataScopesRequest_PageToken:
		// Cursor-based 分页已在上面处理
	}

	// 应用 Limit
	roleDepartmentQuery = roleDepartmentQuery.Limit(int(pageSize))

	// 执行查询
	roleDepartmentList, err := roleDepartmentQuery.All(ctx)
	if err != nil {
		return nil, err
	}

	// 收集所有 department_id
	departmentIDs := make([]int, 0, len(roleDepartmentList))
	for _, rd := range roleDepartmentList {
		if rd.DepartmentID > 0 {
			departmentIDs = append(departmentIDs, rd.DepartmentID)
		}
	}

	// 批量查询部门信息
	departmentMap := make(map[int]*lion.Departments)
	if len(departmentIDs) > 0 {
		// 确定需要查询的字段
		selectFields := []string{
			departments.FieldID,
			departments.FieldParentID,
			departments.FieldCode,
			departments.FieldDisplayName,
			departments.FieldDepartmentType,
			departments.FieldDepartmentStatus,
			departments.FieldSortOrder,
		}

		// 如果 View 为 FULL，添加更多字段
		if req.View == adminv1.View_FULL {
			selectFields = append(selectFields,
				departments.FieldCreatedBy,
				departments.FieldUpdatedBy,
				departments.FieldCreatedAt,
				departments.FieldUpdatedAt,
				departments.FieldDescription,
			)
		}

		departmentList, err := db.Departments.Query().
			Select(selectFields...).
			Where(departments.IDIn(departmentIDs...)).
			All(ctx)
		if err != nil {
			return nil, err
		}

		for _, dept := range departmentList {
			departmentMap[dept.ID] = dept
		}
	}

	// 转换为响应格式
	for _, rd := range roleDepartmentList {
		if rd.DepartmentID == 0 {
			continue
		}

		dept, ok := departmentMap[rd.DepartmentID]
		if !ok {
			// 部门不存在，跳过
			continue
		}

		department := &adminv1.Department{
			Id:          int32(dept.ID),
			ParentId:    int32(dept.ParentID),
			Code:        dept.Code,
			DisplayName: dept.DisplayName,
			Type:        adminv1.Department_Type(dept.DepartmentType),
			Status:      adminv1.Department_Status(dept.DepartmentStatus),
			SortOrder:   int32(dept.SortOrder),
		}

		// 如果 View 为 FULL，加载更多详细信息
		if req.View == adminv1.View_FULL {
			department.CreatedBy = dept.CreatedBy
			department.UpdatedBy = dept.UpdatedBy
			department.CreatedAt = timestamppb.New(dept.CreatedAt)
			department.UpdatedAt = timestamppb.New(dept.UpdatedAt)
			if dept.Description != "" {
				department.Description = dept.Description
			}
		}

		result.Departments = append(result.Departments, department)
	}

	// 构造 next_page_token（仅用于 cursor-based 分页）
	switch req.GetPagination().(type) {
	case *adminv1.ListRoleDataScopesRequest_PageToken:
		// 只有在使用 cursor-based 分页时才生成 next_page_token
		if len(roleDepartmentList) == int(pageSize) && len(roleDepartmentList) > 0 {
			last := roleDepartmentList[len(roleDepartmentList)-1].ID
			tokenData, _ := json.Marshal(last)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}

	return result, nil
}
