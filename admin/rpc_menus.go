package admin

import (
	"context"
	"fmt"
	"sort"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion/groupmenus"
	"github.com/grpc-kit/pkg/lion/groups"
	"github.com/grpc-kit/pkg/lion/groupusers"
	"github.com/grpc-kit/pkg/lion/menus"
	"github.com/grpc-kit/pkg/lion/users"
	"github.com/grpc-kit/pkg/rpc"
)

// ListMenus 获取菜单列表
func (a *KnownAdminAPI) ListMenus(ctx context.Context, req *adminv1.ListMenusRequest) (*adminv1.ListMenusResponse, error) {
	result := &adminv1.ListMenusResponse{}

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

		// TODO; 如果用户组列表为空，则添加默认的 "guest" 用户组
		gs = append(gs, "guest")
	}

	// 根据用户组从 db 中获取 id 列表
	gins, err := a.config.db.Groups.Query().
		Select(
			groups.FieldID,
		).
		Where(
			groups.NameIn(gs...),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	for _, gid := range gins {
		gids = append(gids, gid.ID)
	}

	// 根据用户组 ID 列表获取菜单
	mins, err := a.config.db.GroupMenus.Query().
		Select(
			groupmenus.FieldMenuID,
		).
		Where(
			groupmenus.GroupIDIn(gids...),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	mids := make([]int, 0)
	for _, x := range mins {
		mids = append(mids, x.MenuID)
	}

	// 根据菜单 ID 获取菜单详情
	rids, err := a.config.db.Menus.Query().
		Select(
			menus.FieldID,
			menus.FieldParentID,
			menus.FieldName,
			menus.FieldPath,
			menus.FieldLocale,
			menus.FieldIcon,
			menus.FieldSortWeight,
			menus.FieldEnabled,
			menus.FieldHideInMenu,
			menus.FieldHideChildrenInMenu,
		).
		Where(
			menus.IDIn(mids...),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	// 构建树状菜单
	menuMap := make(map[int32]*adminv1.Menu)
	var roots []*adminv1.Menu

	for _, m := range rids {
		menu := &adminv1.Menu{
			Id:                 int32(m.ID),
			ParentId:           int32(m.ParentID),
			Name:               m.Name,
			Path:               m.Path,
			Locale:             m.Locale,
			Icon:               m.Icon,
			SortWeight:         int32(m.SortWeight),
			Enabled:            m.Enabled,
			HideInMenu:         m.HideInMenu,
			HideChildrenInMenu: m.HideChildrenInMenu,
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
		return roots[i].SortWeight < roots[j].SortWeight
	})

	// TODO；写入该用户的缓存

	result.Menus = roots

	return result, nil
}
