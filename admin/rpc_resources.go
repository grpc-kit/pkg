package admin

import (
	"context"
	"fmt"
	"sort"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion/permissions"
	"github.com/grpc-kit/pkg/lion/policies"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/resources"
	"github.com/grpc-kit/pkg/lion/resourcescopes"
	"github.com/grpc-kit/pkg/lion/rolepermissions"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/scopes"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ListResources 获取资源列表
func (a *KnownAdminAPI) ListResources(ctx context.Context, req *adminv1.ListResourcesRequest) (*adminv1.ListResourcesResponse, error) {
	result := &adminv1.ListResourcesResponse{}

	// TODO；读取该用户的缓存

	db, err := a.GetLionClient()
	if err != nil {
		// 如果未开启数据库时直接返回空资源而不是错误
		return result, nil
	}

	// 从 jwt 中获取用户组
	gs, ok := rpc.GetGroupsFromContext(ctx)
	if !ok {
		return result, fmt.Errorf("not found groups")
	}

	if len(gs) == 0 {
		return result, nil
	}

	permissionsWhere := make([]predicate.Permissions, 0)
	permissionsWhere = append(permissionsWhere, permissions.HasLionRolePermissionsWith(
		rolepermissions.HasLionRolesWith(
			roles.CodeIn(gs...),
		),
	))

	policiesWhere := make([]predicate.Policies, 0)
	if req.PolicyType != 0 {
		policiesWhere = append(policiesWhere, policies.PolicyTypeEQ(int(req.PolicyType)))
	}
	if req.PolicyStatus != 0 {
		policiesWhere = append(policiesWhere, policies.PolicyStatusEQ(int(req.PolicyStatus)))
	}
	if len(policiesWhere) > 0 {
		permissionsWhere = append(permissionsWhere, permissions.HasLionPoliciesWith(policiesWhere...))
	}

	// 1 查询对应角色所有的资源归属
	resourceScopeList, err := db.Permissions.
		Query().
		Select(
			permissions.FieldResourceScopeID,
		).
		Where(
			permissionsWhere...,
		).
		Unique(true).
		All(ctx)
	if err != nil {
		return nil, err
	}

	if len(resourceScopeList) == 0 {
		return result, nil
	}

	resourceScopeAllID := make([]int, 0)
	for _, scope := range resourceScopeList {
		resourceScopeAllID = append(resourceScopeAllID, scope.ResourceScopeID)
	}

	// 2 判断是否过滤资源作用域
	scopeID := 0
	if req.ScopeType != 0 && req.ScopeName != "" {
		scopeID, err = db.Scopes.Query().Where(scopes.ScopeTypeEQ(int(req.ScopeType)), scopes.CodeEQ(req.ScopeName)).OnlyID(ctx)
		if err != nil {
			return nil, err
		}
	}

	// 3 获取资源列表
	resourcesWhere := make([]predicate.Resources, 0)

	resourceScopesWhere := make([]predicate.ResourceScopes, 0)
	if scopeID != 0 {
		resourceScopesWhere = append(resourceScopesWhere, resourcescopes.ScopeIDEQ(scopeID))
	}
	resourceScopesWhere = append(resourceScopesWhere, resourcescopes.IDIn(resourceScopeAllID...))

	resourcesWhere = append(resourcesWhere, resources.HasLionResourceScopesWith(resourceScopesWhere...))

	if req.ResourceType != 0 {
		resourcesWhere = append(resourcesWhere, resources.ResourceTypeEQ(int(req.ResourceType)))
	}
	if req.ResourceStatus != 0 {
		resourcesWhere = append(resourcesWhere, resources.ResourceStatusEQ(int(req.ResourceStatus)))
	}

	resList, err := db.Resources.
		Query().
		Where(
			resourcesWhere...,
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	switch req.Structure.String() {
	case adminv1.Structure_TREE.String():
		// 构建树状菜单
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
				// Scope:        adminv1.Resource_Scope(m.ResourceScope),
				Status:     adminv1.Resource_Status(m.ResourceStatus),
				Visibility: adminv1.Resource_Visibility(m.Visibility),
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
			result.Resources = append(result.Resources, &adminv1.Resource{
				Id:          int64(m.ID),
				ParentId:    m.ParentID,
				Code:        m.Code,
				DisplayName: m.DisplayName,
				SortOrder:   int32(m.SortOrder),
				Type:        adminv1.Resource_Type(m.ResourceType),
				// Scope:        adminv1.Resource_Scope(m.ResourceScope),
				Status:     adminv1.Resource_Status(m.ResourceStatus),
				Visibility: adminv1.Resource_Visibility(m.Visibility),
				/*
					Hidden:       m.Hidden,
					HideChildren: m.HideChildren,
				*/
				Locator:   m.Locator,
				Visual:    m.Visual,
				Manifest:  m.Manifest,
				CreatedAt: timestamppb.New(m.CreatedAt),
				UpdatedAt: timestamppb.New(m.UpdatedAt),
			})
		}
	}

	return result, nil
}

// CreateResource 创建资源
func (a *KnownAdminAPI) CreateResource(ctx context.Context, req *adminv1.CreateResourceRequest) (*adminv1.Resource, error) {
	result := &adminv1.Resource{}

	// TODO;
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	_, err = db.Resources.Create().
		SetCode(req.Resource.Code).
		SetResourceType(int(req.Resource.Type)).
		// SetResourceScope(int(req.Resource.Scope)).
		SetParentID(req.Resource.ParentId).
		SetLocator(req.Resource.Locator).
		SetManifest(req.Resource.Manifest).
		SetVisual(req.Resource.Visual).
		SetSortOrder(int(req.Resource.SortOrder)).
		// SetEnabled(req.Resource.Enabled).
		// SetHidden(req.Resource.Hidden).
		// SetHideChildren(req.Resource.HideChildren).
		Save(ctx)

	if err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateResource 更新资源
func (a *KnownAdminAPI) UpdateResource(ctx context.Context, req *adminv1.UpdateResourceRequest) (*adminv1.Resource, error) {
	result := &adminv1.Resource{}

	// TODO;

	return result, nil
}

// DeleteResource 删除资源
func (a *KnownAdminAPI) DeleteResource(ctx context.Context, req *adminv1.DeleteResourceRequest) (*emptypb.Empty, error) {

	// TODO;

	return &emptypb.Empty{}, nil
}
