package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/grouproles"
	"github.com/grpc-kit/pkg/lion/roledepartments"
	"github.com/grpc-kit/pkg/lion/rolepermissions"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/userroles"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ListRoles 创建用户
func (a *KnownAdminAPI) ListRoles(ctx context.Context, req *adminv1.ListRolesRequest) (*adminv1.ListRolesResponse, error) {
	result := &adminv1.ListRolesResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	defaultSelect := []string{
		roles.FieldID,
		roles.FieldCode,
		roles.FieldDisplayName,
		roles.FieldRoleType,
		roles.FieldRoleStatus,
		roles.FieldSortOrder,
		roles.FieldDescription,
		roles.FieldCreatedAt,
		roles.FieldUpdatedAt,
	}

	roleQuery := db.Roles.Query()

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
		roleQuery = roleQuery.Order(lion.Desc(roles.FieldID))
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

	for _, r := range rl {
		result.Roles = append(result.Roles, &adminv1.Role{
			Id:          int32(r.ID),
			Code:        r.Code,
			DisplayName: r.DisplayName,
			Type:        adminv1.Role_Type(r.RoleType),
			Status:      adminv1.Role_Status(r.RoleStatus),
			SortOrder:   int32(r.SortOrder),
			Description: r.Description,
			CreatedAt:   timestamppb.New(r.CreatedAt),
			UpdatedAt:   timestamppb.New(r.UpdatedAt),
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
		SetCode(req.Role.Code).
		SetDisplayName(req.Role.DisplayName).
		SetDescription(req.Role.Description).
		SetSortOrder(int(req.Role.SortOrder)).
		Save(ctx)
	if err != nil {
		return result, err
	}

	result = &adminv1.Role{
		Id:          int32(role.ID),
		Code:        role.Code,
		DisplayName: role.DisplayName,
		Description: role.Description,
		SortOrder:   int32(role.SortOrder),
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
			case roles.FieldCode:
				x.SetCode(req.Role.Code)
				/*
					case roles.FieldI18nName + ".zh_cn":
						if req.Role.I18NName != nil {
							if req.Role.I18NName.ZhCn != "" {
								x.SetI18nName(I18NNameJSON(req.Role.I18NName))
							}
						}
				*/
			case roles.FieldSortOrder:
				x.SetSortOrder(int(req.Role.SortOrder))
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
			roles.FieldCode,
			roles.FieldDisplayName,
			roles.FieldRoleType,
			roles.FieldRoleStatus,
			roles.FieldSortOrder,
			roles.FieldDescription,
		).Where(
			roles.ID(int(req.Role.Id)),
		).Only(ctx)
		if err != nil {
			return nil, err
		}

		result = &adminv1.Role{
			Id:          int32(q.ID),
			Code:        q.Code,
			DisplayName: q.DisplayName,
			Description: q.Description,
			SortOrder:   int32(q.SortOrder),
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
