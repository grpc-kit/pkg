package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/permissionbindings"
	"github.com/grpc-kit/pkg/lion/permissions"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/resourcescopes"
	"github.com/grpc-kit/pkg/lion/rolepermissions"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ListPermissions 获取权限列表
func (a *KnownAdminAPI) ListPermissions(ctx context.Context, req *adminv1.ListPermissionsRequest) (*adminv1.ListPermissionsResponse, error) {
	result := &adminv1.ListPermissionsResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		// 如果未开启数据库时直接返回空结果而不是错误
		return result, nil
	}

	// 构建查询条件
	permissionsWhere := make([]predicate.Permissions, 0)

	// 过滤条件
	if req.PolicyId != 0 {
		permissionsWhere = append(permissionsWhere, permissions.PolicyIDEQ(int(req.PolicyId)))
	}

	// 构建查询，但先不执行
	permissionQuery := db.Permissions.Query().Where(permissionsWhere...)

	// 处理排序
	if req.OrderBy != "" {
		switch req.OrderBy {
		case "create_time desc":
			permissionQuery = permissionQuery.Order(lion.Desc(permissions.FieldCreatedAt))
		case "create_time asc":
			permissionQuery = permissionQuery.Order(lion.Asc(permissions.FieldCreatedAt))
		case "code desc":
			permissionQuery = permissionQuery.Order(lion.Desc(permissions.FieldCode))
		case "code asc":
			permissionQuery = permissionQuery.Order(lion.Asc(permissions.FieldCode))
		default:
			// 默认按创建时间降序
			permissionQuery = permissionQuery.Order(lion.Desc(permissions.FieldCreatedAt))
		}
	} else {
		// 默认排序
		permissionQuery = permissionQuery.Order(lion.Desc(permissions.FieldCreatedAt))
	}

	// 计算总数（在应用分页前）
	totalSize, err := permissionQuery.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	// 处理分页
	pageSize := GetPageSize(ctx, req.PageSize)

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
			permissionQuery = permissionQuery.Where(permissions.IDGT(lastID))
		}
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListPermissionsRequest_Offset:
		// Offset-based 分页
		permissionQuery = permissionQuery.Offset(int(p.Offset))
	case *adminv1.ListPermissionsRequest_PageToken:
		// Cursor-based 分页已在上面处理
	}

	// 应用 Limit
	permissionQuery = permissionQuery.Limit(int(pageSize))

	// 如果 View 为 FULL，需要预加载策略和资源信息
	if req.View == adminv1.View_FULL {
		permissionQuery = permissionQuery.
			WithLionPolicies().
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
	}

	// 执行查询
	permissionList, err := permissionQuery.All(ctx)
	if err != nil {
		return nil, err
	}

	// 转换为响应格式
	for _, p := range permissionList {
		permission := &adminv1.Permission{
			Id:          int64(p.ID),
			Code:        p.Code,
			DisplayName: p.DisplayName,
			Description: p.Description,
		}

		// 如果 View 为 FULL，加载策略和资源信息
		if req.View == adminv1.View_FULL {
			// 加载策略信息
			if p.Edges.LionPolicies != nil {
				policy := p.Edges.LionPolicies
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
			if p.Edges.LionPermissionBindings != nil {
				resourceMap := make(map[int64]*adminv1.Resource)
				resourceScopesMap := make(map[int64]map[int64]*adminv1.Scope) // resource_id -> scope_id -> scope
				for _, binding := range p.Edges.LionPermissionBindings {
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
	case *adminv1.ListPermissionsRequest_PageToken:
		// 只有在使用 cursor-based 分页时才生成 next_page_token
		if len(permissionList) == int(pageSize) && len(permissionList) > 0 {
			last := permissionList[len(permissionList)-1].ID
			tokenData, _ := json.Marshal(last)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}

	return result, nil
}

// GetPermission 获取单个权限的详细信息
func (a *KnownAdminAPI) GetPermission(ctx context.Context, req *adminv1.GetPermissionRequest) (*adminv1.Permission, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("permission id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 查询权限，并预加载策略和资源信息
	permission, err := db.Permissions.Query().
		Where(permissions.IDEQ(int(req.Id))).
		WithLionPolicies().
		WithLionPermissionBindings(
			func(query *lion.PermissionBindingsQuery) {
				query.WithLionResourceScopes(
					func(query *lion.ResourceScopesQuery) {
						query.WithLionResources().
							WithLionScopes()
					},
				)
			},
		).
		Only(ctx)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("permission not found")
	}

	// 构建返回的权限对象
	result := &adminv1.Permission{
		Id:          int64(permission.ID),
		Code:        permission.Code,
		DisplayName: permission.DisplayName,
		Description: permission.Description,
	}

	// 加载策略信息
	if permission.Edges.LionPolicies != nil {
		policy := permission.Edges.LionPolicies
		result.Policy = &adminv1.Policy{
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
	if permission.Edges.LionPermissionBindings != nil {
		resourceMap := make(map[int64]*adminv1.Resource)
		resourceScopesMap := make(map[int64]map[int64]*adminv1.Scope) // resource_id -> scope_id -> scope
		for _, binding := range permission.Edges.LionPermissionBindings {
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
			result.Resources = append(result.Resources, res)
		}
	}

	return result, nil
}

// CreatePermission 创建权限
func (a *KnownAdminAPI) CreatePermission(ctx context.Context, req *adminv1.CreatePermissionRequest) (*adminv1.Permission, error) {
	if req == nil || req.Permission == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body permission is nil")
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

	// 验证策略是否存在
	if req.Permission.Policy == nil || req.Permission.Policy.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("policy is required")
	}

	policyID := int(req.Permission.Policy.Id)
	_, err = db.Policies.Get(ctx, policyID)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("policy not found")
	}

	// 创建权限
	create := db.Permissions.Create().
		SetCode(req.Permission.Code).
		SetDisplayName(req.Permission.DisplayName).
		SetDescription(req.Permission.Description).
		SetPolicyID(policyID).
		SetCreatedBy(userID).
		SetUpdatedBy(userID)

	newPermission, err := create.Save(ctx)
	if err != nil {
		return nil, err
	}

	// 创建权限与资源的关联（permission_bindings）
	if len(req.Permission.Resources) > 0 {
		// 收集有效的 resource_scope IDs
		resourceScopeIDs := make([]int, 0)
		for _, res := range req.Permission.Resources {
			if res.Id == 0 {
				continue
			}

			// 查找资源对应的 resource_scopes
			// 注意：这里需要根据业务逻辑确定如何关联资源和作用域
			// 暂时假设每个资源都有一个默认的 resource_scope
			resourceScopes, err := db.ResourceScopes.Query().
				Where(resourcescopes.ResourceIDEQ(int(res.Id))).
				All(ctx)
			if err != nil {
				continue
			}

			for _, rs := range resourceScopes {
				resourceScopeIDs = append(resourceScopeIDs, rs.ID)
			}
		}

		// 批量创建 permission_bindings
		if len(resourceScopeIDs) > 0 {
			bindings := make([]*lion.PermissionBindingsCreate, 0, len(resourceScopeIDs))
			for _, rsID := range resourceScopeIDs {
				binding := db.PermissionBindings.Create().
					SetPermissionID(newPermission.ID).
					SetResourceScopeID(rsID)
				bindings = append(bindings, binding)
			}
			_, err = db.PermissionBindings.CreateBulk(bindings...).Save(ctx)
			if err != nil {
				// 如果创建关联失败，删除已创建的权限
				_ = db.Permissions.DeleteOneID(newPermission.ID).Exec(ctx)
				return nil, err
			}
		}
	}

	// 重新查询权限以获取完整信息
	return a.GetPermission(ctx, &adminv1.GetPermissionRequest{Id: int64(newPermission.ID)})
}

// UpdatePermission 更新权限
func (a *KnownAdminAPI) UpdatePermission(ctx context.Context, req *adminv1.UpdatePermissionRequest) (*adminv1.Permission, error) {
	if req == nil || req.Permission == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body permission is nil")
	}

	if req.Permission.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("permission id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 获取更新者用户 ID
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	// 查找要更新的权限
	permission, err := db.Permissions.Get(ctx, int(req.Permission.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("permission not found")
	}

	// 构建更新操作
	update := permission.Update()

	// 根据请求设置更新字段
	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		for _, field := range req.UpdateMask.Paths {
			switch field {
			case permissions.FieldCode:
				update.SetCode(req.Permission.Code)
			case permissions.FieldDisplayName:
				update.SetDisplayName(req.Permission.DisplayName)
			case permissions.FieldDescription:
				update.SetDescription(req.Permission.Description)
			case permissions.FieldPolicyID:
				if req.Permission.Policy != nil && req.Permission.Policy.Id != 0 {
					// 验证策略是否存在
					_, err := db.Policies.Get(ctx, int(req.Permission.Policy.Id))
					if err != nil {
						return nil, errs.NotFound(ctx).WithMessage("policy not found")
					}
					update.SetPolicyID(int(req.Permission.Policy.Id))
				}
			}
		}
		// 始终更新 UpdatedBy
		update.SetUpdatedBy(userID)
	} else {
		// 如果没有指定更新字段，则更新所有字段
		policyID := permission.PolicyID
		if req.Permission.Policy != nil && req.Permission.Policy.Id != 0 {
			// 验证策略是否存在
			_, err := db.Policies.Get(ctx, int(req.Permission.Policy.Id))
			if err != nil {
				return nil, errs.NotFound(ctx).WithMessage("policy not found")
			}
			policyID = int(req.Permission.Policy.Id)
		}

		update.
			SetCode(req.Permission.Code).
			SetDisplayName(req.Permission.DisplayName).
			SetDescription(req.Permission.Description).
			SetPolicyID(policyID).
			SetUpdatedBy(userID)
	}

	// 执行更新
	_, err = update.Save(ctx)
	if err != nil {
		return nil, err
	}

	// 如果提供了资源列表，更新关联的资源
	if len(req.Permission.Resources) > 0 {
		// 删除现有的 permission_bindings
		_, err = db.PermissionBindings.Delete().
			Where(permissionbindings.PermissionIDEQ(int(req.Permission.Id))).
			Exec(ctx)
		if err != nil {
			return nil, err
		}

		// 创建新的 permission_bindings
		resourceScopeIDs := make([]int, 0)
		for _, res := range req.Permission.Resources {
			if res.Id == 0 {
				continue
			}

			// 查找资源对应的 resource_scopes
			resourceScopes, err := db.ResourceScopes.Query().
				Where(resourcescopes.ResourceIDEQ(int(res.Id))).
				All(ctx)
			if err != nil {
				continue
			}

			for _, rs := range resourceScopes {
				resourceScopeIDs = append(resourceScopeIDs, rs.ID)
			}
		}

		// 批量创建 permission_bindings
		if len(resourceScopeIDs) > 0 {
			bindings := make([]*lion.PermissionBindingsCreate, 0, len(resourceScopeIDs))
			for _, rsID := range resourceScopeIDs {
				binding := db.PermissionBindings.Create().
					SetPermissionID(int(req.Permission.Id)).
					SetResourceScopeID(rsID)
				bindings = append(bindings, binding)
			}
			_, err = db.PermissionBindings.CreateBulk(bindings...).Save(ctx)
			if err != nil {
				return nil, err
			}
		}
	}

	// 重新查询权限以获取完整信息
	return a.GetPermission(ctx, &adminv1.GetPermissionRequest{Id: req.Permission.Id})
}

// DeletePermission 删除权限
func (a *KnownAdminAPI) DeletePermission(ctx context.Context, req *adminv1.DeletePermissionRequest) (*emptypb.Empty, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("permission id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查权限是否存在
	_, err = db.Permissions.Get(ctx, int(req.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("permission not found")
	}

	// 检查是否存在关联的角色权限（通过 lion_role_permissions 表）
	rolePermissionsCount, err := db.RolePermissions.Query().
		Where(rolepermissions.PermissionIDEQ(int(req.Id))).
		Count(ctx)
	if err == nil && rolePermissionsCount > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("cannot delete permission with associated roles")
	}

	// 删除关联的 permission_bindings
	_, err = db.PermissionBindings.Delete().
		Where(permissionbindings.PermissionIDEQ(int(req.Id))).
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	// 执行删除
	err = db.Permissions.DeleteOneID(int(req.Id)).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
