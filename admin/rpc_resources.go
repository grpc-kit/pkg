package admin

import (
	"context"
	"fmt"
	"sort"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/resources"
	"github.com/grpc-kit/pkg/lion/rolepermissions"
	"github.com/grpc-kit/pkg/lion/roles"
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

	// 用户组 ID 集合
	gids := make([]int, 0)

	// TODO;
	// 1. 需定义默认用户组
	// 2. 如果 oidc 不支持 groups 时如何处理
	if len(gs) == 0 {
		// TODO; 从 lion_group_users 中查询用户组
		// TODO; 如果用户组列表为空，则添加默认的 "guest" 用户组
		gs = append(gs, "guest")
	}

	// 根据用户组从 db 中获取 id 列表
	gins, err := db.Roles.Query().
		Select(
			roles.FieldID,
		).
		Where(
			roles.NameIn(gs...),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	for _, gid := range gins {
		gids = append(gids, gid.ID)
	}

	// 根据用户组 ID 列表获取菜单
	mins, err := db.RolePermissions.Query().
		Select(
			rolepermissions.FieldPermissionID,
		).
		Where(
			rolepermissions.RoleIDIn(gids...),
		).WithLionPermissions(func(query *lion.PermissionsQuery) {
	}).
		All(ctx)
	if err != nil {
		return nil, err
	}

	mids := make([]int, 0)
	for _, x := range mins {
		if x.Edges.LionPermissions != nil {
			mids = append(mids, x.Edges.LionPermissions.ResourceID)
		}
	}

	// 根据菜单 ID 获取菜单详情
	rids, err := db.Resources.Query().
		Select(
			resources.FieldID,
			resources.FieldParentID,
			resources.FieldName,
			// resources.FieldI18nName,
			resources.FieldSortOrder,
			resources.FieldResourceType,
			resources.FieldResourceScope,
			resources.FieldEnabled,
			resources.FieldHidden,
			resources.FieldHideChildren,
			resources.FieldPath,
			resources.FieldIcon,
			resources.FieldComponent,
			resources.FieldCreatedAt,
			resources.FieldUpdatedAt,
		).
		Where(
			resources.IDIn(mids...),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	// 构建树状菜单
	menuMap := make(map[int32]*adminv1.Resource)
	var roots []*adminv1.Resource

	for _, m := range rids {
		menu := &adminv1.Resource{
			Id:       int32(m.ID),
			ParentId: int32(m.ParentID),
			Name:     m.Name,
			// I18NName:     m.I18nName,
			DisplayName:  I18NName(m.Name),
			SortOrder:    int32(m.SortOrder),
			Type:         adminv1.Resource_Type(m.ResourceType),
			Scope:        adminv1.Resource_Scope(m.ResourceScope),
			Enabled:      m.Enabled,
			Hidden:       m.Hidden,
			HideChildren: m.HideChildren,
			Path:         m.Path,
			Icon:         m.Icon,
			Component:    m.Component,
			CreatedAt:    timestamppb.New(m.CreatedAt),
			UpdatedAt:    timestamppb.New(m.UpdatedAt),
		}

		menuMap[int32(m.ID)] = menu
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

	// TODO；写入该用户的缓存

	result.Resources = roots

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
		SetName(req.Resource.Name).
		SetResourceType(int(req.Resource.Type)).
		SetResourceScope(int(req.Resource.Scope)).
		SetParentID(int(req.Resource.ParentId)).
		SetPath(req.Resource.Path).
		SetComponent(req.Resource.Component).
		SetIcon(req.Resource.Icon).
		SetSortOrder(int(req.Resource.SortOrder)).
		SetEnabled(req.Resource.Enabled).
		SetHidden(req.Resource.Hidden).
		SetHideChildren(req.Resource.HideChildren).
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
