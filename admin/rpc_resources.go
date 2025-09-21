package admin

import (
	"context"
	"fmt"
	"sort"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion/resources"
	"github.com/grpc-kit/pkg/lion/roleresources"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ListResources 获取资源列表
func (a *KnownAdminAPI) ListResources(ctx context.Context, req *adminv1.ListResourcesRequest) (*adminv1.ListResourcesResponse, error) {
	result := &adminv1.ListResourcesResponse{}

	// TODO；读取该用户的缓存

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
		/*
			un, ok := rpc.GetUsernameFromContext(ctx)
			if ok {
				uu, err := a.config.db.Users.Query().
					Select(
						users.FieldID,
						users.FieldEmailEncrypted,
					).
					Where(
						users.EmailHashEQ(crypto.SHA256([]byte(un))),
					).
					Only(ctx)
				if err == nil && len(uu.EmailEncrypted) > 0 {
					tu, err := crypto.DecryptAES(a.config.aesKey, uu.EmailEncrypted)
					if err == nil && string(tu) == un {
						// 如果解密成功且用户名与请求中的用户名匹配，则添加到用户组
						tmp, err := a.config.db.GroupUsers.Query().
							Select(
								groupusers.FieldGroupID,
							).
							Where(
								groupusers.UserIDEQ(uu.ID),
							).
							All(ctx)
						if err == nil {
							for _, v := range tmp {
								gids = append(gids, v.GroupID)
							}
						}
					}
				}
			}
		*/

		// TODO; 如果用户组列表为空，则添加默认的 "guest" 用户组
		gs = append(gs, "guest")
	}

	// 根据用户组从 db 中获取 id 列表
	gins, err := a.config.db.Roles.Query().
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
	mins, err := a.config.db.RoleResources.Query().
		Select(
			roleresources.FieldResourceID,
		).
		Where(
			roleresources.RoleIDIn(gids...),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	mids := make([]int, 0)
	for _, x := range mins {
		mids = append(mids, x.ResourceID)
	}

	// 根据菜单 ID 获取菜单详情
	rids, err := a.config.db.Resources.Query().
		Select(
			resources.FieldID,
			resources.FieldParentID,
			resources.FieldName,
			resources.FieldI18nName,
			resources.FieldOrderWeight,
			resources.FieldType,
			resources.FieldScope,
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
			Id:           int32(m.ID),
			ParentId:     int32(m.ParentID),
			Name:         m.Name,
			I18NName:     I18NNameParse(m.I18nName),
			OrderWeight:  int32(m.OrderWeight),
			Type:         adminv1.Resource_Type(m.Type),
			Scope:        adminv1.Resource_Scope(m.Scope),
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
		return roots[i].OrderWeight < roots[j].OrderWeight
	})

	// TODO；写入该用户的缓存

	result.Resources = roots

	return result, nil
}

// CreateResource 创建资源
func (a *KnownAdminAPI) CreateResource(ctx context.Context, req *adminv1.CreateResourceRequest) (*adminv1.Resource, error) {
	result := &adminv1.Resource{}

	// TODO;

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
