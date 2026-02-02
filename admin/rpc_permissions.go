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
	"github.com/grpc-kit/pkg/lion/rolepermissions"
	"google.golang.org/protobuf/types/known/emptypb"
)

// lionPermissionBindingToProto 将 lion PermissionBindings（含预加载的 resource_scope -> resource/scopes）转为 adminv1.Permission_Binding。
// 权限资源仅通过 Permission.Bindings 暴露，已废弃的 Permission.Resources 不再使用。
func lionPermissionBindingToProto(binding *lion.PermissionBindings) *adminv1.Permission_Binding {
	if binding == nil {
		return nil
	}
	out := &adminv1.Permission_Binding{
		Id:              int64(binding.ID),
		ResourceScopeId: int64(binding.ResourceScopeID),
		IsRecursive:     binding.IsRecursive,
	}
	if binding.Edges.LionResourceScopes != nil {
		rs := binding.Edges.LionResourceScopes
		if rs.Edges.LionResources != nil {
			res := rs.Edges.LionResources
			out.Resources = &adminv1.Resource{
				Id:          int64(res.ID),
				ParentId:    res.ParentID,
				Code:        res.Code,
				DisplayName: res.DisplayName,
				SortOrder:   int32(res.SortOrder),
				Type:        adminv1.Resource_Type(res.ResourceType),
				Status:      adminv1.Resource_Status(res.ResourceStatus),
				Visibility:  adminv1.Visibility(res.Visibility),
				Locator:     res.Locator,
				Visual:      res.Visual,
				Manifest:    res.Manifest,
				Description: res.Description,
			}
			if rs.Edges.LionScopes != nil {
				s := rs.Edges.LionScopes
				out.Resources.Scopes = append(out.Resources.Scopes, &adminv1.Scope{
					Id:          int64(s.ID),
					Code:        s.Code,
					DisplayName: s.DisplayName,
					Type:        adminv1.Scope_Type(s.ScopeType),
				})
			}
		}
	}
	return out
}

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

			// 加载权限绑定资源（permission_bindings -> resource_scopes -> resources）
			if p.Edges.LionPermissionBindings != nil {
				for _, binding := range p.Edges.LionPermissionBindings {
					if pb := lionPermissionBindingToProto(binding); pb != nil {
						permission.Bindings = append(permission.Bindings, pb)
					}
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

	// 加载权限绑定资源（permission_bindings -> resource_scopes -> resources）
	if permission.Edges.LionPermissionBindings != nil {
		for _, binding := range permission.Edges.LionPermissionBindings {
			if pb := lionPermissionBindingToProto(binding); pb != nil {
				result.Bindings = append(result.Bindings, pb)
			}
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

	// 创建权限绑定（permission_bindings），使用 req.Permission.Bindings
	if len(req.Permission.Bindings) > 0 {
		builders := make([]*lion.PermissionBindingsCreate, 0, len(req.Permission.Bindings))
		for _, b := range req.Permission.Bindings {
			if b.ResourceScopeId == 0 {
				continue
			}
			// 校验 resource_scope 存在
			if _, err := db.ResourceScopes.Get(ctx, int(b.ResourceScopeId)); err != nil {
				_ = db.Permissions.DeleteOneID(newPermission.ID).Exec(ctx)
				return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("resource_scope_id %d not found", b.ResourceScopeId))
			}
			builders = append(builders, db.PermissionBindings.Create().
				SetPermissionID(newPermission.ID).
				SetResourceScopeID(int(b.ResourceScopeId)).
				SetIsRecursive(b.IsRecursive))
		}
		if len(builders) > 0 {
			_, err = db.PermissionBindings.CreateBulk(builders...).Save(ctx)
			if err != nil {
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
			case "bindings":
				// bindings 在下面统一同步，此处仅标记需要更新
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

	// 若请求中带有 bindings，则同步权限绑定（全量替换）
	shouldSyncBindings := len(req.Permission.Bindings) > 0
	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		for _, p := range req.UpdateMask.Paths {
			if p == "bindings" {
				shouldSyncBindings = true
				break
			}
		}
	}
	if shouldSyncBindings {
		_, err = db.PermissionBindings.Delete().
			Where(permissionbindings.PermissionIDEQ(int(req.Permission.Id))).
			Exec(ctx)
		if err != nil {
			return nil, err
		}
		if len(req.Permission.Bindings) > 0 {
			builders := make([]*lion.PermissionBindingsCreate, 0, len(req.Permission.Bindings))
			for _, b := range req.Permission.Bindings {
				if b.ResourceScopeId == 0 {
					continue
				}
				if _, err := db.ResourceScopes.Get(ctx, int(b.ResourceScopeId)); err != nil {
					return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("resource_scope_id %d not found", b.ResourceScopeId))
				}
				builders = append(builders, db.PermissionBindings.Create().
					SetPermissionID(int(req.Permission.Id)).
					SetResourceScopeID(int(b.ResourceScopeId)).
					SetIsRecursive(b.IsRecursive))
			}
			if len(builders) > 0 {
				_, err = db.PermissionBindings.CreateBulk(builders...).Save(ctx)
				if err != nil {
					return nil, err
				}
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
