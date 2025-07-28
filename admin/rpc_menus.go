package admin

import (
	"context"
	"fmt"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion/groupmenus"
	"github.com/grpc-kit/pkg/lion/groups"
	"github.com/grpc-kit/pkg/lion/menus"
	"github.com/grpc-kit/pkg/rpc"
)

// GetMenus 获取菜单列表
func (a *KnownAdminAPI) GetMenus(ctx context.Context, req *adminv1.GetMenusRequest) (*adminv1.GetMenusResponse, error) {
	result := &adminv1.GetMenusResponse{}

	// 从 jwt 中获取用户组
	gs, ok := rpc.GetGroupsFromContext(ctx)
	if !ok {
		return result, fmt.Errorf("not found groups")
	}

	// 根据用户组从 db 中获取 id 列表
	gins, err := a.config.db.Groups.Query().
		Select("id").
		Where(groups.NameIn(gs...)).
		All(ctx)
	if err != nil {
		return nil, err
	}

	gids := make([]int, 0)
	for _, gid := range gins {
		gids = append(gids, gid.ID)
	}

	// 根据用户组 ID 列表获取菜单
	mins, err := a.config.db.GroupMenus.Query().
		Select("menu_id").
		Where(groupmenus.GroupIDIn(gids...)).
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
		Select("id", "parent_id", "name", "path", "locale", "icon", "sort_weight", "enabled", "hide_in_menu", "hide_children_in_menu").
		Where(menus.IDIn(mids...)).
		All(ctx)
	if err != nil {
		return nil, err
	}

	for _, v := range rids {
		a.logger.Infof("GetMenus: %+v", v)
	}

	return result, nil
}
