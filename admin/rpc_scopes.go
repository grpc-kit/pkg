package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/resources"
	"github.com/grpc-kit/pkg/lion/resourcescopes"
	"github.com/grpc-kit/pkg/lion/scopes"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ListScopes 获取作用域列表
func (a *KnownAdminAPI) ListScopes(ctx context.Context, req *adminv1.ListScopesRequest) (*adminv1.ListScopesResponse, error) {
	result := &adminv1.ListScopesResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		// 如果未开启数据库时直接返回空结果而不是错误
		return result, nil
	}

	defaultSelect := []string{
		scopes.FieldID,
		scopes.FieldCode,
		scopes.FieldScopeType,
		scopes.FieldDisplayName,
		scopes.FieldCreatedAt,
		scopes.FieldUpdatedAt,
	}

	scopeQuery := db.Scopes.Query()

	// 构建过滤条件
	scopeWhere := make([]predicate.Scopes, 0)

	if req.ScopeType != 0 {
		scopeWhere = append(scopeWhere, scopes.ScopeTypeEQ(int(req.ScopeType)))
	}

	if req.ScopeName != "" {
		scopeWhere = append(scopeWhere, scopes.CodeEQ(req.ScopeName))
	}

	if len(scopeWhere) > 0 {
		scopeQuery = scopeQuery.Where(scopeWhere...)
	}

	// 处理排序
	if req.OrderBy != "" {
		switch req.OrderBy {
		case "create_time desc":
			scopeQuery = scopeQuery.Order(lion.Desc(scopes.FieldCreatedAt))
		case "create_time asc":
			scopeQuery = scopeQuery.Order(lion.Asc(scopes.FieldCreatedAt))
		case "code asc":
			scopeQuery = scopeQuery.Order(lion.Asc(scopes.FieldCode))
		case "code desc":
			scopeQuery = scopeQuery.Order(lion.Desc(scopes.FieldCode))
		default:
			scopeQuery = scopeQuery.Order(lion.Desc(scopes.FieldID))
		}
	} else {
		// 默认按 ID 降序
		scopeQuery = scopeQuery.Order(lion.Desc(scopes.FieldID))
	}

	// 计算总数（在应用分页前）
	totalSize, err := scopeQuery.Clone().Count(ctx)
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
			scopeQuery = scopeQuery.Where(scopes.IDGT(lastID))
		}
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListScopesRequest_Offset:
		// Offset-based 分页
		scopeQuery = scopeQuery.Offset(int(p.Offset))
	case *adminv1.ListScopesRequest_PageToken:
		// Cursor-based 分页已在上面处理
	}

	// 应用 Limit
	scopeQuery = scopeQuery.Limit(int(pageSize))

	// 执行查询
	scopeList, err := scopeQuery.Select(defaultSelect...).All(ctx)
	if err != nil {
		return nil, err
	}

	// 转换结果
	for _, s := range scopeList {
		scope := &adminv1.Scope{
			Id:          int64(s.ID),
			Code:        s.Code,
			DisplayName: s.DisplayName,
			Type:        adminv1.Scope_Type(s.ScopeType),
		}

		// 注意：数据库中不存在description字段，但proto中有定义
		// 如果将来添加了description字段，可以在这里设置
		result.Scopes = append(result.Scopes, scope)
	}

	// 如果还有更多结果，生成 next_page_token
	if len(scopeList) == int(pageSize) && len(scopeList) > 0 {
		lastScope := scopeList[len(scopeList)-1]
		tokenData, _ := json.Marshal(lastScope.ID)
		result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
	}

	return result, nil
}

// CreateScope 创建作用域
func (a *KnownAdminAPI) CreateScope(ctx context.Context, req *adminv1.CreateScopeRequest) (*adminv1.Scope, error) {
	result := &adminv1.Scope{}

	if req.Scope == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body scope is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 创建作用域
	newScope, err := db.Scopes.Create().
		SetCode(req.Scope.Code).
		SetDisplayName(req.Scope.DisplayName).
		SetScopeType(int(req.Scope.Type)).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	result = &adminv1.Scope{
		Id:          int64(newScope.ID),
		Code:        newScope.Code,
		DisplayName: newScope.DisplayName,
		Type:        adminv1.Scope_Type(newScope.ScopeType),
	}

	// 注意：数据库中不存在description字段，但proto中有定义
	// 如果将来添加了description字段，可以在这里设置

	return result, nil
}

// UpdateScope 更新作用域
func (a *KnownAdminAPI) UpdateScope(ctx context.Context, req *adminv1.UpdateScopeRequest) (*adminv1.Scope, error) {
	result := &adminv1.Scope{}

	if req.Scope == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body scope is nil")
	}

	if req.Scope.Id == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("scope id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 查找要更新的作用域
	scope, err := db.Scopes.Get(ctx, int(req.Scope.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("scope not found")
	}

	// 构建更新操作
	update := scope.Update()

	// 根据 UpdateMask 更新字段
	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		for _, field := range req.UpdateMask.Paths {
			switch field {
			case "code":
				update.SetCode(req.Scope.Code)
			case "display_name":
				update.SetDisplayName(req.Scope.DisplayName)
			case "type":
				update.SetScopeType(int(req.Scope.Type))
			}
		}
	} else {
		// 如果没有指定更新字段，则更新所有字段
		update.
			SetCode(req.Scope.Code).
			SetDisplayName(req.Scope.DisplayName).
			SetScopeType(int(req.Scope.Type))
	}

	// 执行更新
	updatedScope, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}

	result = &adminv1.Scope{
		Id:          int64(updatedScope.ID),
		Code:        updatedScope.Code,
		DisplayName: updatedScope.DisplayName,
		Type:        adminv1.Scope_Type(updatedScope.ScopeType),
	}

	// 注意：数据库中不存在description字段，但proto中有定义
	// 如果将来添加了description字段，可以在这里设置

	return result, nil
}

// DeleteScope 删除作用域
func (a *KnownAdminAPI) DeleteScope(ctx context.Context, req *adminv1.DeleteScopeRequest) (*emptypb.Empty, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("scope id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查作用域是否存在
	_, err = db.Scopes.Get(ctx, int(req.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("scope not found")
	}

	// 检查是否存在关联的资源作用域
	// 根据schema定义，删除scope时会级联删除resource_scopes，但我们可以先检查
	resourceScopesCount, err := db.ResourceScopes.Query().
		Where(resourcescopes.ScopeIDEQ(int(req.Id))).
		Count(ctx)
	if err != nil {
		return nil, err
	}

	if resourceScopesCount > 0 {
		// 根据schema定义有级联删除，但我们可以选择不允许删除有关联的scope
		// 或者允许删除（级联删除会自动处理）
		// 这里我们允许删除，因为schema中定义了级联删除
	}

	// 执行删除
	_, err = db.Scopes.Delete().Where(scopes.ID(int(req.Id))).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// ListScopeResources 获取作用域关联的资源列表
func (a *KnownAdminAPI) ListScopeResources(ctx context.Context, req *adminv1.ListScopeResourcesRequest) (*adminv1.ListScopeResourcesResponse, error) {
	result := &adminv1.ListScopeResourcesResponse{}

	if req.ScopeId == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("scope_id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查作用域是否存在
	_, err = db.Scopes.Get(ctx, int(req.ScopeId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("scope not found")
	}

	// 构建查询条件：通过 resource_scopes 关联表查询资源
	resourcesWhere := make([]predicate.Resources, 0)
	resourceScopesWhere := []predicate.ResourceScopes{resourcescopes.ScopeIDEQ(int(req.ScopeId))}
	resourcesWhere = append(resourcesWhere, resources.HasLionResourceScopesWith(resourceScopesWhere...))

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
			resourceQuery = resourceQuery.Where(resources.IDGT(lastID))
		}
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListScopeResourcesRequest_Offset:
		// Offset-based 分页
		resourceQuery = resourceQuery.Offset(int(p.Offset))
	case *adminv1.ListScopeResourcesRequest_PageToken:
		// Cursor-based 分页已在上面处理
	}

	// 应用 Limit
	resourceQuery = resourceQuery.Limit(int(pageSize))

	// 执行查询
	resList, err := resourceQuery.All(ctx)
	if err != nil {
		return nil, err
	}

	// 查询 resource_scope_id 映射（用于 scope_resource_items，供权限绑定等使用）
	if len(resList) > 0 {
		resourceIDs := make([]int, 0, len(resList))
		for _, r := range resList {
			resourceIDs = append(resourceIDs, r.ID)
		}
		rsList, rsErr := db.ResourceScopes.Query().
			Where(
				resourcescopes.ScopeIDEQ(int(req.ScopeId)),
				resourcescopes.ResourceIDIn(resourceIDs...),
			).
			WithLionResources().
			All(ctx)
		if rsErr == nil {
			resourceToProto := func(m *lion.Resources) *adminv1.Resource {
				if m == nil {
					return nil
				}
				return &adminv1.Resource{
					Id:          int64(m.ID),
					ParentId:    m.ParentID,
					Code:        m.Code,
					DisplayName: m.DisplayName,
					SortOrder:   int32(m.SortOrder),
					Type:        adminv1.Resource_Type(m.ResourceType),
					Status:      adminv1.Resource_Status(m.ResourceStatus),
					Visibility:  adminv1.Resource_Visibility(m.Visibility),
					Locator:     m.Locator,
					Visual:      m.Visual,
					Manifest:    m.Manifest,
					Description: m.Description,
					CreatedAt:   timestamppb.New(m.CreatedAt),
					UpdatedAt:   timestamppb.New(m.UpdatedAt),
				}
			}
			for _, rs := range rsList {
				item := &adminv1.ScopeResourceItem{
					ResourceScopeId: int64(rs.ID),
					Resource:        resourceToProto(rs.Edges.LionResources),
				}
				if item.Resource != nil {
					result.ScopeResourceItems = append(result.ScopeResourceItems, item)
				}
			}
		}
	}

	// 处理结构（树状或列表）
	switch req.Structure.String() {
	case adminv1.Structure_TREE.String():
		// 构建树状菜单
		// 注意：树状结构的分页比较特殊，这里先构建完整的树，实际项目中可能需要调整策略
		menuMap := make(map[int64]*adminv1.Resource)
		var roots []*adminv1.Resource

		for _, m := range resList {
			menu := &adminv1.Resource{
				Id:          int64(m.ID),
				ParentId:    m.ParentID,
				Code:        m.Code,
				DisplayName: m.DisplayName,
				SortOrder:   int32(m.SortOrder),
				Type:        adminv1.Resource_Type(m.ResourceType),
				Status:      adminv1.Resource_Status(m.ResourceStatus),
				Visibility:  adminv1.Resource_Visibility(m.Visibility),
				Locator:     m.Locator,
				Visual:      m.Visual,
				Manifest:    m.Manifest,
				Description: m.Description,
				CreatedAt:   timestamppb.New(m.CreatedAt),
				UpdatedAt:   timestamppb.New(m.UpdatedAt),
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
		// 列表结构
		for _, m := range resList {
			result.Resources = append(result.Resources, &adminv1.Resource{
				Id:          int64(m.ID),
				ParentId:    m.ParentID,
				Code:        m.Code,
				DisplayName: m.DisplayName,
				SortOrder:   int32(m.SortOrder),
				Type:        adminv1.Resource_Type(m.ResourceType),
				Status:      adminv1.Resource_Status(m.ResourceStatus),
				Visibility:  adminv1.Resource_Visibility(m.Visibility),
				Locator:     m.Locator,
				Visual:      m.Visual,
				Manifest:    m.Manifest,
				Description: m.Description,
				CreatedAt:   timestamppb.New(m.CreatedAt),
				UpdatedAt:   timestamppb.New(m.UpdatedAt),
			})
		}
	}

	// 构造 next_page_token（仅用于 cursor-based 分页）
	switch req.GetPagination().(type) {
	case *adminv1.ListScopeResourcesRequest_PageToken:
		// 只有在使用 cursor-based 分页时才生成 next_page_token
		if len(resList) == int(pageSize) && len(resList) > 0 {
			last := resList[len(resList)-1].ID
			tokenData, _ := json.Marshal(last)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}

	return result, nil
}

// DeleteScopeResource 删除作用域与资源的关联
func (a *KnownAdminAPI) DeleteScopeResource(ctx context.Context, req *adminv1.DeleteScopeResourceRequest) (*emptypb.Empty, error) {
	if req.ScopeId == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("scope_id is required")
	}

	if req.ResourceId == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("resource_id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查作用域是否存在
	_, err = db.Scopes.Get(ctx, int(req.ScopeId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("scope not found")
	}

	// 检查资源是否存在
	_, err = db.Resources.Get(ctx, int(req.ResourceId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("resource not found")
	}

	// 查找并删除关联关系
	resourceScope, err := db.ResourceScopes.Query().
		Where(
			resourcescopes.ScopeIDEQ(int(req.ScopeId)),
			resourcescopes.ResourceIDEQ(int(req.ResourceId)),
		).
		Only(ctx)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("scope resource relationship not found")
	}

	// 执行删除
	_, err = db.ResourceScopes.Delete().Where(resourcescopes.ID(resourceScope.ID)).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// CreateScopeResources 创建作用域与多个资源的关联
func (a *KnownAdminAPI) CreateScopeResources(ctx context.Context, req *adminv1.CreateScopeResourcesRequest) (*adminv1.CreateScopeResourcesResponse, error) {
	result := &adminv1.CreateScopeResourcesResponse{}

	if req.ScopeId == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("scope_id is required")
	}

	if len(req.Resources) == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("resources list is empty")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查作用域是否存在
	_, err = db.Scopes.Get(ctx, int(req.ScopeId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("scope not found")
	}

	// 收集有效的 resource IDs 并验证每个 resource 是否存在
	resourceIDs := make([]int, 0, len(req.Resources))
	resourceIDMap := make(map[int64]*adminv1.Resource)

	for _, resource := range req.Resources {
		if resource.Id == 0 {
			continue
		}

		// 检查资源是否存在
		dbResource, err := db.Resources.Get(ctx, int(resource.Id))
		if err != nil {
			// 如果某个 resource 不存在，跳过不存在的 resource
			continue
		}

		resourceIDs = append(resourceIDs, dbResource.ID)
		// 保存 resource 信息以便后续返回
		resourceIDMap[resource.Id] = &adminv1.Resource{
			Id:          int64(dbResource.ID),
			ParentId:    dbResource.ParentID,
			Code:        dbResource.Code,
			DisplayName: dbResource.DisplayName,
			SortOrder:   int32(dbResource.SortOrder),
			Type:        adminv1.Resource_Type(dbResource.ResourceType),
			Status:      adminv1.Resource_Status(dbResource.ResourceStatus),
			Visibility:  adminv1.Resource_Visibility(dbResource.Visibility),
			Locator:     dbResource.Locator,
			Visual:      dbResource.Visual,
			Manifest:    dbResource.Manifest,
			Description: dbResource.Description,
			CreatedAt:   timestamppb.New(dbResource.CreatedAt),
			UpdatedAt:   timestamppb.New(dbResource.UpdatedAt),
		}
	}

	if len(resourceIDs) == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("no valid resources found")
	}

	// 检查是否已存在关联关系，如果存在则跳过
	existingResourceScopes, err := db.ResourceScopes.Query().
		Where(
			resourcescopes.ScopeIDEQ(int(req.ScopeId)),
			resourcescopes.ResourceIDIn(resourceIDs...),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	// 构建已存在的 resource ID 集合
	existingResourceIDSet := make(map[int]bool)
	for _, rs := range existingResourceScopes {
		existingResourceIDSet[rs.ResourceID] = true
	}

	// 过滤出需要创建的 resource IDs（排除已存在的）
	resourcesToCreate := make([]int, 0)
	for _, resourceID := range resourceIDs {
		if !existingResourceIDSet[resourceID] {
			resourcesToCreate = append(resourcesToCreate, resourceID)
		}
	}

	// 批量创建关联关系
	if len(resourcesToCreate) > 0 {
		allResourceScopes := make([]*lion.ResourceScopesCreate, 0, len(resourcesToCreate))

		for _, resourceID := range resourcesToCreate {
			rs := db.ResourceScopes.Create().
				SetResourceID(resourceID).
				SetScopeID(int(req.ScopeId))

			allResourceScopes = append(allResourceScopes, rs)
		}

		_, err = db.ResourceScopes.CreateBulk(allResourceScopes...).Save(ctx)
		if err != nil {
			return nil, err
		}
	}

	// 返回所有关联的资源（包括已存在的和新创建的）
	for _, resource := range req.Resources {
		if resource.Id != 0 {
			if r, ok := resourceIDMap[resource.Id]; ok {
				result.Resources = append(result.Resources, r)
			}
		}
	}

	return result, nil
}
