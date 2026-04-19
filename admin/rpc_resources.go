package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/permissionbindings"
	"github.com/grpc-kit/pkg/lion/permissions"
	"github.com/grpc-kit/pkg/lion/policies"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/resources"
	"github.com/grpc-kit/pkg/lion/resourcescopes"
	"github.com/grpc-kit/pkg/lion/rolepermissions"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/schema"
	"github.com/grpc-kit/pkg/lion/scopes"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// listResourceAuthFilter 用于在权限图中收窄可见资源；零值表示不按该维度过滤。
// ListResources 可传入请求中的 policy / scope；单资源读写应传空 filter，使用「全并集」与列表默认可见范围一致（不受列表时附带 policy/scope 参数影响）。
type listResourceAuthFilter struct {
	PolicyType   int32
	PolicyStatus int32
	ScopeType    int32
	ScopeName    string
}

// allowedResourceIDsForContext 按与 ListResources 相同的 Lion 角色树、角色权限、permission_bindings、资源树递归规则，解析当前用户可访问的资源 ID 集合。
// superAdmin 为 true 时不返回 allowed（调用方视为不裁剪）；err 表示上下文缺失 groups 等错误。
func (a *KnownAdminAPI) allowedResourceIDsForContext(ctx context.Context, db *lion.Client, f listResourceAuthFilter) (superAdmin bool, allowed map[int]struct{}, err error) {
	gs, ok := rpc.GetGroupsFromContext(ctx)
	if !ok {
		return false, nil, fmt.Errorf("not found groups")
	}
	if len(gs) == 0 {
		return false, map[int]struct{}{}, nil
	}
	for _, g := range gs {
		if g == "superadmin" {
			return true, nil, nil
		}
	}
	roleRows, err := db.Roles.Query().Select(roles.FieldID).Where(roles.CodeIn(gs...)).All(ctx)
	if err != nil {
		return false, nil, err
	}
	if len(roleRows) == 0 {
		return false, map[int]struct{}{}, nil
	}
	parentRoleIDs := make([]int, len(roleRows))
	for i, r := range roleRows {
		parentRoleIDs[i] = r.ID
	}
	childRoleIDs, err := a.getAllChildRoleIDs(ctx, db, parentRoleIDs)
	if err != nil {
		return false, nil, err
	}
	allRoleIDs := mergeUniqueInts(parentRoleIDs, childRoleIDs)

	permissionsWhere := make([]predicate.Permissions, 0)
	permissionsWhere = append(permissionsWhere, permissions.HasLionRolePermissionsWith(
		rolepermissions.HasLionRolesWith(
			roles.IDIn(allRoleIDs...),
		),
	))
	policiesWhere := make([]predicate.Policies, 0)
	if f.PolicyType != 0 {
		policiesWhere = append(policiesWhere, policies.PolicyTypeEQ(int(f.PolicyType)))
	}
	if f.PolicyStatus != 0 {
		policiesWhere = append(policiesWhere, policies.PolicyStatusEQ(int(f.PolicyStatus)))
	}
	if len(policiesWhere) > 0 {
		permissionsWhere = append(permissionsWhere, permissions.HasLionPoliciesWith(policiesWhere...))
	}

	bindingList, err := db.PermissionBindings.
		Query().
		Select(
			permissionbindings.FieldResourceScopeID,
			permissionbindings.FieldIsRecursive,
		).
		Where(
			permissionbindings.HasLionPermissionsWith(permissionsWhere...),
		).
		All(ctx)
	if err != nil {
		return false, nil, err
	}
	if len(bindingList) == 0 {
		return false, map[int]struct{}{}, nil
	}

	scopeRecursive := make(map[int]bool)
	resourceScopeAllID := make([]int, 0)
	for _, b := range bindingList {
		resourceScopeAllID = append(resourceScopeAllID, b.ResourceScopeID)
		if b.IsRecursive {
			scopeRecursive[b.ResourceScopeID] = true
		} else if _, set := scopeRecursive[b.ResourceScopeID]; !set {
			scopeRecursive[b.ResourceScopeID] = false
		}
	}

	scopeID := 0
	if f.ScopeType != 0 && f.ScopeName != "" {
		scopeID, err = db.Scopes.Query().Where(scopes.ScopeTypeEQ(int(f.ScopeType)), scopes.CodeEQ(f.ScopeName)).OnlyID(ctx)
		if err != nil {
			return false, nil, err
		}
	}

	rsWhere := []predicate.ResourceScopes{resourcescopes.IDIn(resourceScopeAllID...)}
	if scopeID != 0 {
		rsWhere = append(rsWhere, resourcescopes.ScopeIDEQ(scopeID))
	}
	rsList, err := db.ResourceScopes.Query().Where(rsWhere...).Select(resourcescopes.FieldID, resourcescopes.FieldResourceID).All(ctx)
	if err != nil {
		return false, nil, err
	}
	if len(rsList) == 0 {
		return false, map[int]struct{}{}, nil
	}

	recursiveRootIDs := make(map[int]struct{})
	allowedIDs := make(map[int]struct{})
	for _, rs := range rsList {
		allowedIDs[rs.ResourceID] = struct{}{}
		if scopeRecursive[rs.ID] {
			recursiveRootIDs[rs.ResourceID] = struct{}{}
		}
	}
	if len(recursiveRootIDs) > 0 {
		allRes, err := db.Resources.Query().Select(resources.FieldID, resources.FieldParentID).All(ctx)
		if err != nil {
			return false, nil, err
		}
		children := make(map[int64][]int)
		for _, r := range allRes {
			pid := r.ParentID
			children[pid] = append(children[pid], r.ID)
		}
		for rootID := range recursiveRootIDs {
			collectDescendantIDs(int64(rootID), children, allowedIDs)
		}
	}
	return false, allowedIDs, nil
}

// ensureResourceIDInAccessScope 非 superadmin 时要求 resourceID 落在 allowed 集合中；否则返回 NotFound（与「资源不存在」统一，避免泄漏）。
func ensureResourceIDInAccessScope(ctx context.Context, superAdmin bool, allowed map[int]struct{}, resourceID int) error {
	if superAdmin {
		return nil
	}
	if _, ok := allowed[resourceID]; !ok {
		return errs.NotFound(ctx).WithMessage("resource not found")
	}
	return nil
}

// ListResources 获取资源列表
func (a *KnownAdminAPI) ListResources(ctx context.Context, req *adminv1.ListResourcesRequest) (*adminv1.ListResourcesResponse, error) {
	result := &adminv1.ListResourcesResponse{}

	// TODO；读取该用户的缓存

	db, err := a.GetLionClient()
	if err != nil {
		// 如果未开启数据库时直接返回空资源而不是错误
		return result, nil
	}

	hasSuperAdmin, allowedIDs, err := a.allowedResourceIDsForContext(ctx, db, listResourceAuthFilter{
		PolicyType:   req.PolicyType,
		PolicyStatus: req.PolicyStatus,
		ScopeType:    req.ScopeType,
		ScopeName:    req.ScopeName,
	})
	if err != nil {
		return result, err
	}

	// 3 获取资源列表
	resourcesWhere := make([]predicate.Resources, 0)

	if !hasSuperAdmin {
		if len(allowedIDs) == 0 {
			return result, nil
		}
		resourcesWhere = append(resourcesWhere, resources.IDIn(mapKeys(allowedIDs)...))
	} else {
		// superadmin 可以查看所有资源，但仍需要支持资源作用域过滤
		if req.ScopeType != 0 && req.ScopeName != "" {
			scopeID, err := db.Scopes.Query().Where(scopes.ScopeTypeEQ(int(req.ScopeType)), scopes.CodeEQ(req.ScopeName)).OnlyID(ctx)
			if err != nil {
				return nil, err
			}
			if scopeID != 0 {
				resourceScopesWhere := []predicate.ResourceScopes{resourcescopes.ScopeIDEQ(scopeID)}
				resourcesWhere = append(resourcesWhere, resources.HasLionResourceScopesWith(resourceScopesWhere...))
			}
		}
	}

	if req.ResourceType != 0 {
		resourcesWhere = append(resourcesWhere, resources.ResourceTypeEQ(int(req.ResourceType)))
	}
	if req.ResourceStatus != 0 {
		resourcesWhere = append(resourcesWhere, resources.ResourceStatusEQ(int(req.ResourceStatus)))
	}

	// 构建查询，但先不执行
	resourceQuery := db.Resources.Query().Where(resourcesWhere...)

	// 处理排序
	if req.OrderBy != "" {
		switch req.OrderBy {
		case "sort_order asc":
			resourceQuery = resourceQuery.Order(lion.Asc(resources.FieldSortOrder))
		case "sort_order desc":
			resourceQuery = resourceQuery.Order(lion.Desc(resources.FieldSortOrder))
		case "create_time desc":
			resourceQuery = resourceQuery.Order(lion.Desc(resources.FieldCreatedAt))
		case "create_time asc":
			resourceQuery = resourceQuery.Order(lion.Asc(resources.FieldCreatedAt))
		default:
			// 默认按 sort_order 升序，然后按 ID 升序
			resourceQuery = resourceQuery.Order(lion.Asc(resources.FieldSortOrder), lion.Asc(resources.FieldID))
		}
	} else {
		// 默认排序
		resourceQuery = resourceQuery.Order(lion.Asc(resources.FieldSortOrder), lion.Asc(resources.FieldID))
	}

	// 计算总数（在应用分页前）
	totalSize, err := resourceQuery.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	// 处理分页
	pageSize := GetPageSizeByStructure(ctx, req.PageSize, req.Structure)

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
			resourceQuery = resourceQuery.Where(resources.IDGT(lastID))
		}
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListResourcesRequest_Offset:
		// Offset-based 分页
		resourceQuery = resourceQuery.Offset(int(p.Offset))
	case *adminv1.ListResourcesRequest_PageToken:
		// Cursor-based 分页已在上面处理
	}

	// 应用 Limit
	resourceQuery = resourceQuery.Limit(int(pageSize))

	// 执行查询
	// 如果 View 为 FULL，需要预加载作用域信息
	if req.View == adminv1.View_VIEW_FULL {
		resourceQuery = resourceQuery.WithLionResourceScopes(
			func(query *lion.ResourceScopesQuery) {
				query.WithLionScopes()
			},
		)
	}

	resList, err := resourceQuery.All(ctx)
	if err != nil {
		return nil, err
	}

	// 如果 View 为 FULL，收集作用域信息
	var resourceScopesMap map[int][]*adminv1.Scope
	if req.View == adminv1.View_VIEW_FULL {
		resourceScopesMap = make(map[int][]*adminv1.Scope)
		for _, res := range resList {
			if res.Edges.LionResourceScopes != nil {
				scopes := make([]*adminv1.Scope, 0)
				for _, rs := range res.Edges.LionResourceScopes {
					if rs.Edges.LionScopes != nil {
						s := rs.Edges.LionScopes
						scopes = append(scopes, &adminv1.Scope{
							Id:          int64(s.ID),
							Code:        s.Code,
							DisplayName: s.DisplayName,
							Type:        adminv1.Scope_Type(s.ScopeType),
							Protected:   s.Protected,
						})
					}
				}
				resourceScopesMap[res.ID] = scopes
			}
		}
	}

	switch req.Structure.String() {
	case adminv1.Structure_STRUCTURE_TREE.String():
		// 构建树状菜单
		// 注意：树状结构的分页比较特殊，这里先构建完整的树，实际项目中可能需要调整策略
		menuMap := make(map[int64]*adminv1.Resource)
		var roots []*adminv1.Resource

		for _, m := range resList {
			menu := &adminv1.Resource{
				Id:          int64(m.ID),
				ParentId:    m.ParentID,
				Code:        m.Code,
				Name:        m.Name,
				DisplayName: m.DisplayName,
				SortOrder:   int32(m.SortOrder),
				Type:        adminv1.Resource_Type(m.ResourceType),
				// Scope:        adminv1.Resource_Scope(m.ResourceScope),
				Status:     adminv1.Resource_Status(m.ResourceStatus),
				Visibility: adminv1.Visibility(m.Visibility),
				/*
					Hidden:       m.Hidden,
					HideChildren: m.HideChildren,
				*/
				Locator:   m.Locator,
				Visual:    m.Visual,
				Manifest:  m.Manifest,
				CreatedAt: timestamppb.New(m.CreatedAt),
				UpdatedAt: timestamppb.New(m.UpdatedAt),
			}

			// 如果 View 为 FULL，填充作用域列表
			if req.View == adminv1.View_VIEW_FULL {
				if scopes, ok := resourceScopesMap[m.ID]; ok {
					menu.Scopes = scopes
				}
			}

			menuMap[int64(m.ID)] = menu
		}

		for _, menu := range menuMap {
			if menu.ParentId == 0 {
				roots = append(roots, menu)
				continue
			}

			if parent, ok := menuMap[menu.ParentId]; ok {
				parent.Children = append(parent.Children, menu)
			}
		}

		// 可选：对根菜单排序
		sort.Slice(roots, func(i, j int) bool {
			return roots[i].SortOrder < roots[j].SortOrder
		})

		result.Resources = roots
	default:
		for _, m := range resList {
			resource := &adminv1.Resource{
				Id:          int64(m.ID),
				ParentId:    m.ParentID,
				Code:        m.Code,
				Name:        m.Name,
				DisplayName: m.DisplayName,
				SortOrder:   int32(m.SortOrder),
				Type:        adminv1.Resource_Type(m.ResourceType),
				// Scope:        adminv1.Resource_Scope(m.ResourceScope),
				Status:     adminv1.Resource_Status(m.ResourceStatus),
				Visibility: adminv1.Visibility(m.Visibility),
				/*
					Hidden:       m.Hidden,
					HideChildren: m.HideChildren,
				*/
				Locator:   m.Locator,
				Visual:    m.Visual,
				Manifest:  m.Manifest,
				CreatedAt: timestamppb.New(m.CreatedAt),
				UpdatedAt: timestamppb.New(m.UpdatedAt),
			}

			// 如果 View 为 FULL，填充作用域列表
			if req.View == adminv1.View_VIEW_FULL {
				if scopes, ok := resourceScopesMap[m.ID]; ok {
					resource.Scopes = scopes
				}
			}

			result.Resources = append(result.Resources, resource)
		}
	}

	// 构造 next_page_token（仅用于 cursor-based 分页）
	switch req.GetPagination().(type) {
	case *adminv1.ListResourcesRequest_PageToken:
		// 只有在使用 cursor-based 分页时才生成 next_page_token
		if len(resList) == int(pageSize) && len(resList) > 0 {
			last := resList[len(resList)-1].ID
			tokenData, _ := json.Marshal(last)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}

	return result, nil
}

// CreateResource 创建资源
func (a *KnownAdminAPI) CreateResource(ctx context.Context, req *adminv1.CreateResourceRequest) (*adminv1.Resource, error) {
	if req == nil || req.Resource == nil {
		return nil, fmt.Errorf("request body resource is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	code, err := schema.EnsureCode(req.Resource.Code)
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	req.Resource.Code = code
	req.Resource.Name = normalizeResourceName(req.Resource.Name, req.Resource.Type, req.Resource.Code, req.Resource.Locator)

	if req.Resource.ParentId == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("parent_id cannot be 0 when creating resource")
	}

	super, allowed, err := a.allowedResourceIDsForContext(ctx, db, listResourceAuthFilter{})
	if err != nil {
		return nil, err
	}
	if err := ensureResourceIDInAccessScope(ctx, super, allowed, int(req.Resource.ParentId)); err != nil {
		return nil, err
	}

	parentResource, err := db.Resources.Get(ctx, int(req.Resource.ParentId))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.InvalidArgument(ctx).WithMessage("parent resource not found")
		}
		return nil, err
	}

	if parentResource.ResourceType != int(req.Resource.Type) {
		return nil, errs.InvalidArgument(ctx).WithMessage("resource type must match parent resource type")
	}

	// 获取创建者用户 ID
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	// 设置默认值
	sortOrder := int(req.Resource.SortOrder)
	if sortOrder == 0 {
		sortOrder = 100 // 默认排序权重
	}

	// 创建资源
	newResource, err := db.Resources.Create().
		SetCode(req.Resource.Code).
		SetName(req.Resource.Name).
		SetDisplayName(req.Resource.DisplayName).
		SetResourceType(int(req.Resource.Type)).
		SetResourceStatus(int(req.Resource.Status)).
		SetVisibility(int(req.Resource.Visibility)).
		SetParentID(req.Resource.ParentId).
		SetLocator(req.Resource.Locator).
		SetVisual(req.Resource.Visual).
		SetManifest(req.Resource.Manifest).
		SetSortOrder(sortOrder).
		SetDescription(req.Resource.Description).
		SetCreatedBy(userID).
		SetUpdatedBy(userID).
		Save(ctx)

	if err != nil {
		return nil, err
	}

	// 构建返回的资源对象
	result := &adminv1.Resource{
		Id:          int64(newResource.ID),
		ParentId:    newResource.ParentID,
		Code:        newResource.Code,
		Name:        newResource.Name,
		DisplayName: newResource.DisplayName,
		SortOrder:   int32(newResource.SortOrder),
		Type:        adminv1.Resource_Type(newResource.ResourceType),
		Status:      adminv1.Resource_Status(newResource.ResourceStatus),
		Visibility:  adminv1.Visibility(newResource.Visibility),
		Locator:     newResource.Locator,
		Visual:      newResource.Visual,
		Manifest:    newResource.Manifest,
		Description: newResource.Description,
		CreatedAt:   timestamppb.New(newResource.CreatedAt),
		UpdatedAt:   timestamppb.New(newResource.UpdatedAt),
	}

	// 处理 metadata（如果存在）
	if len(req.Resource.Metadata) > 0 {
		result.Metadata = req.Resource.Metadata
	}

	return result, nil
}

// UpdateResource 更新资源
func (a *KnownAdminAPI) UpdateResource(ctx context.Context, req *adminv1.UpdateResourceRequest) (*adminv1.Resource, error) {
	if req == nil || req.Resource == nil {
		return nil, fmt.Errorf("request body resource is nil")
	}

	if req.Resource.Id == 0 {
		return nil, fmt.Errorf("resource id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	super, allowed, err := a.allowedResourceIDsForContext(ctx, db, listResourceAuthFilter{})
	if err != nil {
		return nil, err
	}
	if err := ensureResourceIDInAccessScope(ctx, super, allowed, int(req.Resource.Id)); err != nil {
		return nil, err
	}

	// 获取更新者用户 ID
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	// 查找要更新的资源
	resource, err := db.Resources.Get(ctx, int(req.Resource.Id))
	if err != nil {
		return nil, err
	}

	shouldUpdateParentID := req.UpdateMask == nil || len(req.UpdateMask.Paths) == 0
	if !shouldUpdateParentID {
		for _, field := range req.UpdateMask.Paths {
			if field == resources.FieldParentID {
				shouldUpdateParentID = true
				break
			}
		}
	}
	if shouldUpdateParentID && resource.ParentID == 0 && req.Resource.ParentId != resource.ParentID {
		return nil, errs.InvalidArgument(ctx).WithMessage("root resource parent_id cannot be changed")
	}

	if req.Resource.Code != "" {
		code, err := schema.EnsureCode(req.Resource.Code)
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
		}
		req.Resource.Code = code
	}
	req.Resource.Name = normalizeResourceName(req.Resource.Name, req.Resource.Type, req.Resource.Code, req.Resource.Locator)

	// 构建更新操作
	update := resource.Update()

	// 根据请求设置更新字段
	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		for _, field := range req.UpdateMask.Paths {
			switch field {
			case resources.FieldCode:
				update.SetCode(req.Resource.Code)
			case resources.FieldName:
				update.SetName(req.Resource.Name)
			case resources.FieldDisplayName:
				update.SetDisplayName(req.Resource.DisplayName)
			case resources.FieldResourceType:
				update.SetResourceType(int(req.Resource.Type))
			case resources.FieldResourceStatus:
				update.SetResourceStatus(int(req.Resource.Status))
			case resources.FieldVisibility:
				update.SetVisibility(int(req.Resource.Visibility))
			case resources.FieldParentID:
				update.SetParentID(req.Resource.ParentId)
			case resources.FieldLocator:
				update.SetLocator(req.Resource.Locator)
			case resources.FieldVisual:
				update.SetVisual(req.Resource.Visual)
			case resources.FieldManifest:
				update.SetManifest(req.Resource.Manifest)
			case resources.FieldSortOrder:
				update.SetSortOrder(int(req.Resource.SortOrder))
			case resources.FieldDescription:
				update.SetDescription(req.Resource.Description)
			}
		}
		// 始终更新 UpdatedBy
		update.SetUpdatedBy(userID)
	} else {
		// 如果没有指定更新字段，则更新所有字段
		update.
			SetCode(req.Resource.Code).
			SetName(req.Resource.Name).
			SetDisplayName(req.Resource.DisplayName).
			SetResourceType(int(req.Resource.Type)).
			SetResourceStatus(int(req.Resource.Status)).
			SetVisibility(int(req.Resource.Visibility)).
			SetParentID(req.Resource.ParentId).
			SetLocator(req.Resource.Locator).
			SetVisual(req.Resource.Visual).
			SetManifest(req.Resource.Manifest).
			SetSortOrder(int(req.Resource.SortOrder)).
			SetDescription(req.Resource.Description).
			SetUpdatedBy(userID)
	}

	// 执行更新
	updatedResource, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}

	// 构建返回的资源对象
	result := &adminv1.Resource{
		Id:          int64(updatedResource.ID),
		ParentId:    updatedResource.ParentID,
		Code:        updatedResource.Code,
		Name:        updatedResource.Name,
		DisplayName: updatedResource.DisplayName,
		SortOrder:   int32(updatedResource.SortOrder),
		Type:        adminv1.Resource_Type(updatedResource.ResourceType),
		Status:      adminv1.Resource_Status(updatedResource.ResourceStatus),
		Visibility:  adminv1.Visibility(updatedResource.Visibility),
		Locator:     updatedResource.Locator,
		Visual:      updatedResource.Visual,
		Manifest:    updatedResource.Manifest,
		Description: updatedResource.Description,
		CreatedAt:   timestamppb.New(updatedResource.CreatedAt),
		UpdatedAt:   timestamppb.New(updatedResource.UpdatedAt),
	}

	// 处理 metadata（如果存在）
	if len(req.Resource.Metadata) > 0 {
		result.Metadata = req.Resource.Metadata
	}

	return result, nil
}

// DeleteResource 删除资源
func (a *KnownAdminAPI) DeleteResource(ctx context.Context, req *adminv1.DeleteResourceRequest) (*emptypb.Empty, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("resource id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	super, allowed, err := a.allowedResourceIDsForContext(ctx, db, listResourceAuthFilter{})
	if err != nil {
		return nil, err
	}
	if err := ensureResourceIDInAccessScope(ctx, super, allowed, int(req.Id)); err != nil {
		return nil, err
	}

	// 检查资源是否存在
	_, err = db.Resources.Get(ctx, int(req.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("resource not found")
	}

	// 检查是否存在子节点（parent_id == 资源 id）
	childrenCount, err := db.Resources.Query().
		Where(resources.ParentIDEQ(int64(req.Id))).
		Count(ctx)
	if err != nil {
		return nil, err
	}

	if childrenCount > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("cannot delete resource with child nodes")
	}

	// 执行删除
	err = db.Resources.DeleteOneID(int(req.Id)).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// CreateResourceScopes 创建资源与多个作用域的关联
func (a *KnownAdminAPI) CreateResourceScopes(ctx context.Context, req *adminv1.CreateResourceScopesRequest) (*adminv1.CreateResourceScopesResponse, error) {
	result := &adminv1.CreateResourceScopesResponse{}

	if req.ResourceId == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("resource_id is required")
	}

	if len(req.Scopes) == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("scopes list is empty")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	super, allowed, err := a.allowedResourceIDsForContext(ctx, db, listResourceAuthFilter{})
	if err != nil {
		return nil, err
	}
	if err := ensureResourceIDInAccessScope(ctx, super, allowed, int(req.ResourceId)); err != nil {
		return nil, err
	}

	// 检查资源是否存在
	_, err = db.Resources.Get(ctx, int(req.ResourceId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("resource not found")
	}

	// 收集有效的 scope IDs 并验证每个 scope 是否存在
	scopeIDs := make([]int, 0, len(req.Scopes))
	scopeIDMap := make(map[int64]*adminv1.Scope)

	for _, scope := range req.Scopes {
		if scope.Id == 0 {
			continue
		}

		// 检查作用域是否存在
		dbScope, err := db.Scopes.Get(ctx, int(scope.Id))
		if err != nil {
			// 如果某个 scope 不存在，可以选择跳过或返回错误
			// 这里选择跳过不存在的 scope
			continue
		}

		scopeIDs = append(scopeIDs, dbScope.ID)
		// 保存 scope 信息以便后续返回
		scopeIDMap[scope.Id] = &adminv1.Scope{
			Id:          int64(dbScope.ID),
			Code:        dbScope.Code,
			DisplayName: dbScope.DisplayName,
			Type:        adminv1.Scope_Type(dbScope.ScopeType),
			Protected:   dbScope.Protected,
		}
	}

	if len(scopeIDs) == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("no valid scopes found")
	}

	// 检查是否已存在关联关系，如果存在则跳过
	existingResourceScopes, err := db.ResourceScopes.Query().
		Where(
			resourcescopes.ResourceIDEQ(int(req.ResourceId)),
			resourcescopes.ScopeIDIn(scopeIDs...),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	// 构建已存在的 scope ID 集合
	existingScopeIDSet := make(map[int]bool)
	for _, rs := range existingResourceScopes {
		existingScopeIDSet[rs.ScopeID] = true
	}

	// 过滤出需要创建的 scope IDs（排除已存在的）
	scopesToCreate := make([]int, 0)
	for _, scopeID := range scopeIDs {
		if !existingScopeIDSet[scopeID] {
			scopesToCreate = append(scopesToCreate, scopeID)
		}
	}

	// 批量创建关联关系
	if len(scopesToCreate) > 0 {
		allResourceScopes := make([]*lion.ResourceScopesCreate, 0, len(scopesToCreate))

		for _, scopeID := range scopesToCreate {
			rs := db.ResourceScopes.Create().
				SetResourceID(int(req.ResourceId)).
				SetScopeID(scopeID)

			allResourceScopes = append(allResourceScopes, rs)
		}

		_, err = db.ResourceScopes.CreateBulk(allResourceScopes...).Save(ctx)
		if err != nil {
			return nil, err
		}
	}

	// 返回所有关联的作用域（包括已存在的和新创建的）
	for _, scope := range req.Scopes {
		if scope.Id != 0 {
			if s, ok := scopeIDMap[scope.Id]; ok {
				result.Scopes = append(result.Scopes, s)
			}
		}
	}

	return result, nil
}

// GetResource 获取单个资源的详细信息
func (a *KnownAdminAPI) GetResource(ctx context.Context, req *adminv1.GetResourceRequest) (*adminv1.Resource, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("resource id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	super, allowed, err := a.allowedResourceIDsForContext(ctx, db, listResourceAuthFilter{})
	if err != nil {
		return nil, err
	}
	if err := ensureResourceIDInAccessScope(ctx, super, allowed, int(req.Id)); err != nil {
		return nil, err
	}

	// 查询资源，并预加载作用域信息
	resource, err := db.Resources.Query().
		Where(resources.IDEQ(int(req.Id))).
		WithLionResourceScopes(
			func(query *lion.ResourceScopesQuery) {
				query.WithLionScopes()
			},
		).
		Only(ctx)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("resource not found")
	}

	// 构建返回的资源对象
	result := &adminv1.Resource{
		Id:          int64(resource.ID),
		ParentId:    resource.ParentID,
		Code:        resource.Code,
		Name:        resource.Name,
		DisplayName: resource.DisplayName,
		SortOrder:   int32(resource.SortOrder),
		Type:        adminv1.Resource_Type(resource.ResourceType),
		Status:      adminv1.Resource_Status(resource.ResourceStatus),
		Visibility:  adminv1.Visibility(resource.Visibility),
		Locator:     resource.Locator,
		Visual:      resource.Visual,
		Manifest:    resource.Manifest,
		Description: resource.Description,
		CreatedBy:   resource.CreatedBy,
		UpdatedBy:   resource.UpdatedBy,
		CreatedAt:   timestamppb.New(resource.CreatedAt),
		UpdatedAt:   timestamppb.New(resource.UpdatedAt),
	}

	// 加载关联的作用域列表
	if resource.Edges.LionResourceScopes != nil {
		scopes := make([]*adminv1.Scope, 0)
		for _, rs := range resource.Edges.LionResourceScopes {
			if rs.Edges.LionScopes != nil {
				s := rs.Edges.LionScopes
				scopes = append(scopes, &adminv1.Scope{
					Id:          int64(s.ID),
					Code:        s.Code,
					DisplayName: s.DisplayName,
					Type:        adminv1.Scope_Type(s.ScopeType),
					Protected:   s.Protected,
				})
			}
		}
		result.Scopes = scopes
	}

	return result, nil
}

// collectDescendantIDs 从根节点起 BFS 收集所有子孙资源 ID 并加入 allowedIDs。
func collectDescendantIDs(rootID int64, children map[int64][]int, allowedIDs map[int]struct{}) {
	queue := []int{int(rootID)}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		for _, cid := range children[int64(pid)] {
			allowedIDs[cid] = struct{}{}
			queue = append(queue, cid)
		}
	}
}

// mapKeys 返回 map[int]struct{} 的所有 key，用于 resources.IDIn。
func mapKeys(m map[int]struct{}) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// mergeUniqueInts 合并两段 int 切片并去重，保持先 a 后 b 的稳定顺序。
func mergeUniqueInts(a, b []int) []int {
	seen := make(map[int]struct{}, len(a)+len(b))
	out := make([]int, 0, len(a)+len(b))
	for _, id := range a {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	for _, id := range b {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func normalizeResourceName(name string, resourceType adminv1.Resource_Type, code, locator string) string {
	if strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	typePart := strings.ToLower(resourceType.String())
	if typePart == "" || typePart == "type_unspecified" {
		typePart = "resource"
	}
	pathPart := strings.TrimSpace(locator)
	if pathPart == "" {
		pathPart = strings.TrimSpace(code)
	}
	if pathPart == "" {
		pathPart = "unnamed"
	}
	return fmt.Sprintf("grn:admin:default:global:%s:%s", typePart, pathPart)
}
