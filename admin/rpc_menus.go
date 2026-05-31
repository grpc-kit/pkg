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
	"github.com/grpc-kit/pkg/lion/menus"
	"github.com/grpc-kit/pkg/lion/rolemenus"
	"github.com/grpc-kit/pkg/lion/schema"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (a *KnownAdminAPI) getAllowedMenuIDsByRole(ctx context.Context, db *lion.Client, roleIDs []int, minScope int) ([]int, error) {
	if len(roleIDs) == 0 {
		return nil, nil
	}

	items, err := db.RoleMenus.Query().
		Where(
			rolemenus.RoleIDIn(roleIDs...),
			rolemenus.PermissionScopeGTE(minScope),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, nil
	}

	allowed := map[int]struct{}{}
	recursiveRoots := make([]int, 0)
	for _, item := range items {
		allowed[item.MenuID] = struct{}{}
		if item.IsRecursive {
			recursiveRoots = append(recursiveRoots, item.MenuID)
		}
	}

	if len(recursiveRoots) > 0 {
		allMenus, err := db.Menus.Query().
			Select(menus.FieldID, menus.FieldParentID).
			All(ctx)
		if err != nil {
			return nil, err
		}

		childrenByParent := make(map[int64][]int)
		for _, menu := range allMenus {
			childrenByParent[menu.ParentID] = append(childrenByParent[menu.ParentID], menu.ID)
		}

		stack := append([]int(nil), recursiveRoots...)
		for len(stack) > 0 {
			current := stack[len(stack)-1]
			stack = stack[:len(stack)-1]

			for _, childID := range childrenByParent[int64(current)] {
				if _, ok := allowed[childID]; ok {
					continue
				}
				allowed[childID] = struct{}{}
				stack = append(stack, childID)
			}
		}
	}

	ids := make([]int, 0, len(allowed))
	for id := range allowed {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	return ids, nil
}

func menuMetadataToProto(in map[string]interface{}) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = fmt.Sprint(value)
	}
	return out
}

func menuMetadataToEnt(in map[string]string) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func menuVisibilityToProto(code string) adminv1.Visibility {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "global":
		return adminv1.Visibility_VISIBILITY_GLOBAL
	case "subtree":
		return adminv1.Visibility_VISIBILITY_SUBTREE
	case "local":
		return adminv1.Visibility_VISIBILITY_LOCAL
	case "restricted":
		return adminv1.Visibility_VISIBILITY_RESTRICTED
	case "specific":
		return adminv1.Visibility_VISIBILITY_SPECIFIC
	default:
		return adminv1.Visibility_VISIBILITY_UNSPECIFIED
	}
}

func menuVisibilityFromProto(v adminv1.Visibility) string {
	switch v {
	case adminv1.Visibility_VISIBILITY_GLOBAL:
		return "global"
	case adminv1.Visibility_VISIBILITY_SUBTREE:
		return "subtree"
	case adminv1.Visibility_VISIBILITY_LOCAL:
		return "local"
	case adminv1.Visibility_VISIBILITY_RESTRICTED:
		return "restricted"
	case adminv1.Visibility_VISIBILITY_SPECIFIC:
		return "specific"
	default:
		return "global"
	}
}

func hasSuperadminMenuAccess(ctx context.Context) bool {
	groups, ok := rpc.GetGroupsFromContext(ctx)
	if !ok {
		return false
	}
	superadminCode := seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN)
	for _, group := range groups {
		if group == superadminCode {
			return true
		}
	}
	return false
}

// filterMenusByVisibility applies the runtime menu visibility narrowing after role_menus authorization.
// For menus, only RESTRICTED currently has active runtime semantics; other values are retained as attributes.
func filterMenusByVisibility(items []*lion.Menus, userID int64, isSuperadmin bool) []*lion.Menus {
	filtered := make([]*lion.Menus, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		if menuVisibilityToProto(item.Visibility) == adminv1.Visibility_VISIBILITY_RESTRICTED && !isSuperadmin && item.CreatedBy != userID {
			continue
		}
		filtered = append(filtered, item)
	}
	return filtered
}

func pruneMenusWithoutVisibleAncestors(items []*lion.Menus) []*lion.Menus {
	if len(items) == 0 {
		return items
	}
	menuByID := make(map[int]*lion.Menus, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		menuByID[item.ID] = item
	}

	pruned := make([]*lion.Menus, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		currentParentID := item.ParentID
		visible := true
		for currentParentID != 0 {
			parent, ok := menuByID[int(currentParentID)]
			if !ok || parent == nil {
				visible = false
				break
			}
			currentParentID = parent.ParentID
		}
		if visible {
			pruned = append(pruned, item)
		}
	}
	return pruned
}

func lionMenuToProto(in *lion.Menus) *adminv1.Menu {
	if in == nil {
		return nil
	}
	menu := &adminv1.Menu{
		Id:          int64(in.ID),
		ParentId:    in.ParentID,
		Code:        in.Code,
		DisplayName: in.DisplayName,
		RoutePath:   in.RoutePath,
		Component:   in.Component,
		Icon:        in.Icon,
		SortOrder:   int32(in.SortOrder),
		Metadata:    menuMetadataToProto(in.Metadata),
		Visibility:  menuVisibilityToProto(in.Visibility),
		Description: in.Description,
		Protected:   false,
		CreatedBy:   in.CreatedBy,
		UpdatedBy:   in.UpdatedBy,
		CreatedAt:   timestamppb.New(in.CreatedAt),
		UpdatedAt:   timestamppb.New(in.UpdatedAt),
	}

	return menu
}

func filterMenusByCode(items []*lion.Menus, code string) []*lion.Menus {
	code = strings.TrimSpace(code)
	if code == "" {
		return items
	}

	var rootID int64
	found := false
	childrenByParent := make(map[int64][]int64)
	for _, item := range items {
		if item == nil {
			continue
		}
		childrenByParent[item.ParentID] = append(childrenByParent[item.ParentID], int64(item.ID))
		if item.Code == code {
			rootID = int64(item.ID)
			found = true
		}
	}
	if !found {
		return []*lion.Menus{}
	}

	allowed := map[int64]struct{}{rootID: {}}
	queue := []int64{rootID}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, childID := range childrenByParent[current] {
			if _, ok := allowed[childID]; ok {
				continue
			}
			allowed[childID] = struct{}{}
			queue = append(queue, childID)
		}
	}

	filtered := make([]*lion.Menus, 0, len(allowed))
	for _, item := range items {
		if item == nil {
			continue
		}
		if _, ok := allowed[int64(item.ID)]; ok {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func filterMenusByKeyword(items []*lion.Menus, keyword string) []*lion.Menus {
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		return items
	}

	filtered := make([]*lion.Menus, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}
		if strings.Contains(strings.ToLower(item.Code), strings.ToLower(keyword)) ||
			strings.Contains(strings.ToLower(item.DisplayName), strings.ToLower(keyword)) ||
			strings.Contains(strings.ToLower(item.RoutePath), strings.ToLower(keyword)) {
			filtered = append(filtered, item)
		}
	}
	return filtered
}

func sortLionMenus(items []*lion.Menus, orderBy string) {
	switch orderBy {
	case "sort_order desc":
		sort.Slice(items, func(i, j int) bool {
			if items[i].SortOrder == items[j].SortOrder {
				return items[i].ID > items[j].ID
			}
			return items[i].SortOrder > items[j].SortOrder
		})
	case "create_time desc":
		sort.Slice(items, func(i, j int) bool {
			return items[i].CreatedAt.After(items[j].CreatedAt)
		})
	case "create_time asc":
		sort.Slice(items, func(i, j int) bool {
			return items[i].CreatedAt.Before(items[j].CreatedAt)
		})
	default:
		sort.Slice(items, func(i, j int) bool {
			if items[i].SortOrder == items[j].SortOrder {
				return items[i].ID < items[j].ID
			}
			return items[i].SortOrder < items[j].SortOrder
		})
	}
}

func buildMenuTree(items []*lion.Menus) []*adminv1.Menu {
	menuMap := make(map[int64]*adminv1.Menu, len(items))
	roots := make([]*adminv1.Menu, 0)
	for _, item := range items {
		menuMap[int64(item.ID)] = lionMenuToProto(item)
	}
	for _, item := range items {
		current := menuMap[int64(item.ID)]
		if item.ParentID == 0 {
			roots = append(roots, current)
			continue
		}
		if parent, ok := menuMap[item.ParentID]; ok {
			parent.Children = append(parent.Children, current)
		} else {
			roots = append(roots, current)
		}
	}
	var sortMenus func(items []*adminv1.Menu)
	sortMenus = func(items []*adminv1.Menu) {
		sort.Slice(items, func(i, j int) bool {
			if items[i].SortOrder == items[j].SortOrder {
				return items[i].Id < items[j].Id
			}
			return items[i].SortOrder < items[j].SortOrder
		})
		for _, item := range items {
			if len(item.Children) > 0 {
				sortMenus(item.Children)
			}
		}
	}
	sortMenus(roots)
	return roots
}

func (a *KnownAdminAPI) ListMenus(ctx context.Context, req *adminv1.ListMenusRequest) (*adminv1.ListMenusResponse, error) {
	result := &adminv1.ListMenusResponse{}
	db, err := a.GetLionClient()
	if err != nil {
		return result, nil
	}
	roleIDs, err := a.getUserRoleID(ctx)
	if err != nil {
		return nil, err
	}
	allowedMenuIDs, err := a.getAllowedMenuIDsByRole(ctx, db, roleIDs, 1)
	if err != nil {
		return nil, err
	}
	if len(allowedMenuIDs) == 0 {
		result.Menus = make([]*adminv1.Menu, 0)
		result.TotalSize = 0
		result.NextPageToken = ""
		return result, nil
	}
	pageSize := GetPageSizeByStructure(ctx, req.PageSize, req.Structure)
	userID, _ := GetUserID(ctx)
	isSuperadmin := hasSuperadminMenuAccess(ctx)

	list, err := db.Menus.Query().
		Where(menus.IDIn(allowedMenuIDs...)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	list = filterMenusByVisibility(list, userID, isSuperadmin)
	if req.Structure == adminv1.Structure_STRUCTURE_TREE || req.Structure == adminv1.Structure_STRUCTURE_TREE_EXPANDED {
		list = pruneMenusWithoutVisibleAncestors(list)
	}
	if strings.TrimSpace(req.GetCode()) != "" {
		list = filterMenusByCode(list, req.GetCode())
	}
	list = filterMenusByKeyword(list, req.Filter)
	sortLionMenus(list, req.OrderBy)
	result.TotalSize = int32(len(list))

	start := 0
	if req.GetPageToken() != "" {
		data, err := base64.StdEncoding.DecodeString(req.GetPageToken())
		if err != nil {
			return nil, fmt.Errorf("invalid page_token: %w", err)
		}
		var lastID int
		if err := json.Unmarshal(data, &lastID); err != nil {
			return nil, fmt.Errorf("invalid page_token format: %w", err)
		}
		for index, item := range list {
			if item.ID == lastID {
				start = index + 1
				break
			}
		}
	}
	switch p := req.GetPagination().(type) {
	case *adminv1.ListMenusRequest_Offset:
		if p.Offset > 0 {
			start = int(p.Offset)
		}
	}
	if start > len(list) {
		start = len(list)
	}
	end := start + int(pageSize)
	if end > len(list) {
		end = len(list)
	}
	list = list[start:end]

	if req.Structure == adminv1.Structure_STRUCTURE_TREE || req.Structure == adminv1.Structure_STRUCTURE_TREE_EXPANDED {
		result.Menus = buildMenuTree(list)
	} else {
		for _, item := range list {
			result.Menus = append(result.Menus, lionMenuToProto(item))
		}
	}
	if end < int(result.TotalSize) && len(list) > 0 {
		data, _ := json.Marshal(list[len(list)-1].ID)
		result.NextPageToken = base64.StdEncoding.EncodeToString(data)
	}
	return result, nil
}

func (a *KnownAdminAPI) CreateMenu(ctx context.Context, req *adminv1.CreateMenuRequest) (*adminv1.Menu, error) {
	if req == nil || req.Menu == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body menu is nil")
	}
	code, err := schema.EnsureCode(req.Menu.Code)
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	req.Menu.Code = code
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}
	if req.Menu.ParentId > 0 {
		if _, err := db.Menus.Get(ctx, int(req.Menu.ParentId)); err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage("parent menu not found")
		}
	}
	create := db.Menus.Create().
		SetParentID(req.Menu.ParentId).
		SetCode(req.Menu.Code).
		SetDisplayName(req.Menu.DisplayName).
		SetRoutePath(req.Menu.RoutePath).
		SetComponent(req.Menu.Component).
		SetIcon(req.Menu.Icon).
		SetSortOrder(int(req.Menu.SortOrder)).
		SetVisibility(menuVisibilityFromProto(req.Menu.Visibility)).
		SetDescription(req.Menu.Description).
		SetCreatedBy(userID).
		SetUpdatedBy(userID)
	if len(req.Menu.Metadata) > 0 {
		create.SetMetadata(menuMetadataToEnt(req.Menu.Metadata))
	}
	obj, err := create.Save(ctx)
	if err != nil {
		return nil, err
	}
	return lionMenuToProto(obj), nil
}

func (a *KnownAdminAPI) UpdateMenu(ctx context.Context, req *adminv1.UpdateMenuRequest) (*adminv1.Menu, error) {
	if req == nil || req.Menu == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body menu is nil")
	}
	if req.Menu.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("menu id is required")
	}
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}
	obj, err := db.Menus.Get(ctx, int(req.Menu.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("menu not found")
	}
	update := obj.Update()
	apply := func(path string) error {
		switch path {
		case "parent_id":
			if req.Menu.ParentId > 0 {
				if _, err := db.Menus.Get(ctx, int(req.Menu.ParentId)); err != nil {
					return errs.InvalidArgument(ctx).WithMessage("parent menu not found")
				}
			}
			update.SetParentID(req.Menu.ParentId)
		case "code":
			code, err := schema.EnsureCode(req.Menu.Code)
			if err != nil {
				return errs.InvalidArgument(ctx).WithMessage(err.Error())
			}
			update.SetCode(code)
		case "display_name":
			update.SetDisplayName(req.Menu.DisplayName)
		case "route_path":
			update.SetRoutePath(req.Menu.RoutePath)
		case "component":
			update.SetComponent(req.Menu.Component)
		case "icon":
			update.SetIcon(req.Menu.Icon)
		case "sort_order":
			update.SetSortOrder(int(req.Menu.SortOrder))
		case "metadata":
			update.SetMetadata(menuMetadataToEnt(req.Menu.Metadata))
		case "visibility":
			update.SetVisibility(menuVisibilityFromProto(req.Menu.Visibility))
		case "description":
			update.SetDescription(req.Menu.Description)
		case "protected":
			return errs.InvalidArgument(ctx).WithMessage("protected field is managed by system")
		}
		return nil
	}
	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		for _, path := range req.UpdateMask.Paths {
			if err := apply(path); err != nil {
				return nil, err
			}
		}
	} else {
		for _, path := range []string{"parent_id", "resource_id", "code", "display_name", "route_path", "component", "icon", "sort_order", "metadata", "visibility", "description"} {
			if err := apply(path); err != nil {
				return nil, err
			}
		}
	}
	update.SetUpdatedBy(userID)
	saved, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}
	return lionMenuToProto(saved), nil
}

func (a *KnownAdminAPI) DeleteMenu(ctx context.Context, req *adminv1.DeleteMenuRequest) (*emptypb.Empty, error) {
	if req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("menu id is required")
	}
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	rollback := func() { _ = tx.Rollback() }
	obj, err := tx.Menus.Get(ctx, int(req.GetId()))
	if err != nil {
		rollback()
		return nil, errs.NotFound(ctx).WithMessage("menu not found")
	}
	hasChildren, err := tx.Menus.Query().Where(menus.ParentIDEQ(int64(obj.ID))).Exist(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	if hasChildren {
		rollback()
		return nil, errs.InvalidArgument(ctx).WithMessage("cannot delete menu with child nodes")
	}
	if err := tx.Menus.DeleteOneID(obj.ID).Exec(ctx); err != nil {
		rollback()
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
