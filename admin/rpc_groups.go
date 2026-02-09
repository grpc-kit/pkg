package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion/userdepartments"
	"github.com/grpc-kit/pkg/lion/usergroups"
	"github.com/grpc-kit/pkg/lion/userroles"
	"github.com/grpc-kit/pkg/lion/users"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/groups"
	"github.com/grpc-kit/pkg/lion/predicate"
)

// parseGroupParent 解析 parent 为群组 ID，支持 "groups/123" 或 "123"
func parseGroupParent(parent string) (int, error) {
	parent = strings.TrimSpace(parent)
	if parent == "" {
		return 0, fmt.Errorf("parent is empty")
	}
	parent = strings.TrimPrefix(parent, "groups/")
	return strconv.Atoi(strings.TrimSpace(parent))
}

// getGroupType 获取群组类型（返回 adminv1.Group_Type）
func (a *KnownAdminAPI) getGroupType(ctx context.Context, db *lion.Client, groupID int) (adminv1.Group_Type, error) {
	group, err := db.Groups.Get(ctx, groupID)
	if err != nil {
		return adminv1.Group_TYPE_UNSPECIFIED, err
	}
	return adminv1.Group_Type(group.GroupType), nil
}

// isAutoManagedGroupType 判断群组类型是否为自动管理成员类型（不允许手动添加/删除/编辑成员）
func isAutoManagedGroupType(t adminv1.Group_Type) bool {
	return t == adminv1.Group_DEPARTMENT || t == adminv1.Group_ROLE || t == adminv1.Group_DYNAMIC
}

// CreateGroup 创建用户组
func (a *KnownAdminAPI) CreateGroup(ctx context.Context, req *adminv1.CreateGroupRequest) (*adminv1.Group, error) {
	result := &adminv1.Group{}

	if req.Group == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body group is nil")
	}

	// 类型校验：不允许 TYPE_UNSPECIFIED 和 SYSTEM
	groupType := req.Group.Type
	switch groupType {
	case adminv1.Group_TYPE_UNSPECIFIED:
		return result, errs.InvalidArgument(ctx).WithMessage("group type must be specified")
	case adminv1.Group_SYSTEM:
		return result, errs.InvalidArgument(ctx).WithMessage("SYSTEM type groups cannot be created via API")
	case adminv1.Group_DEPARTMENT:
		if req.Group.RefId == 0 {
			return result, errs.InvalidArgument(ctx).WithMessage("ref_id (department_id) is required when type is DEPARTMENT")
		}
	case adminv1.Group_ROLE:
		if req.Group.RefId == 0 {
			return result, errs.InvalidArgument(ctx).WithMessage("ref_id (role_id) is required when type is ROLE")
		}
	case adminv1.Group_EXTERNAL:
		if req.Group.RefExpr == "" {
			return result, errs.InvalidArgument(ctx).WithMessage("ref_expr is required when type is EXTERNAL, format: {\"external_id\":\"...\",\"external_source\":\"...\"}")
		}
	case adminv1.Group_DYNAMIC:
		if req.Group.RefExpr == "" {
			return result, errs.InvalidArgument(ctx).WithMessage("ref_expr (member_rule) is required when type is DYNAMIC")
		}
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	displayName := req.Group.DisplayName
	if displayName == "" {
		displayName = req.Group.Code
	}

	createdBy := req.Group.CreatedBy
	updatedBy := req.Group.UpdatedBy
	if createdBy == 0 || updatedBy == 0 {
		if uid, err := GetUserID(ctx); err == nil {
			if createdBy == 0 {
				createdBy = uid
			}
			if updatedBy == 0 {
				updatedBy = uid
			}
		}
	}

	create := db.Groups.Create().
		SetCode(req.Group.Code).
		SetDisplayName(displayName).
		SetGroupType(int(groupType.Number())).
		SetGroupStatus(int(req.Group.Status.Number())).
		SetSortOrder(int(req.Group.SortOrder)).
		SetMaxMembers(int(req.Group.MaxMembers)).
		SetMetadata(req.Group.Metadata).
		SetRefID(int(req.Group.RefId)).
		SetRefExpr(req.Group.RefExpr).
		SetDescription(req.Group.Description).
		SetCreatedBy(createdBy).
		SetUpdatedBy(updatedBy)

	group, err := create.Save(ctx)
	if err != nil {
		return result, err
	}

	return groupToProto(group, true), nil
}

// ListGroups 列出用户组
func (a *KnownAdminAPI) ListGroups(ctx context.Context, req *adminv1.ListGroupsRequest) (*adminv1.ListGroupsResponse, error) {
	result := &adminv1.ListGroupsResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 构建过滤条件
	where := make([]predicate.Groups, 0)

	// parent: 格式 "groups/123" 表示仅查 parent_id=123 的子群组
	if req.GetParent() != "" {
		if strings.HasPrefix(req.GetParent(), "groups/") {
			parentIDStr := strings.TrimPrefix(req.GetParent(), "groups/")
			parentID, err := strconv.Atoi(strings.TrimSpace(parentIDStr))
			if err == nil {
				where = append(where, groups.ParentID(parentID))
			}
		}
	}

	// group_type / group_status 独立参数过滤
	if req.GetGroupType() > 0 {
		where = append(where, groups.GroupType(int(req.GetGroupType())))
	}
	if req.GetGroupStatus() > 0 {
		where = append(where, groups.GroupStatus(int(req.GetGroupStatus())))
	}

	// code / display_name 独立参数过滤（模糊匹配，不区分大小写）
	if req.GetCode() != "" {
		where = append(where, groups.CodeContainsFold(req.GetCode()))
	}
	if req.GetDisplayName() != "" {
		where = append(where, groups.DisplayNameContainsFold(req.GetDisplayName()))
	}

	// filter: 简单 AIP-160 风格解析，支持 status=2, type=1, parent_id=0, code=xxx, display_name=xxx, ref_id=123
	if req.GetFilter() != "" {
		filterPredicates, err := parseListGroupsFilter(req.GetFilter())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid filter: %v", err))
		}
		where = append(where, filterPredicates...)
	}

	// 未在 filter 中显式包含删除态时，默认排除已软删除
	if !strings.Contains(req.GetFilter(), "deleted_at") && !strings.Contains(req.GetFilter(), "show_deleted") {
		where = append(where, groups.DeletedAtIsNil())
	}

	query := db.Groups.Query().Where(where...)

	// 排序 order_by: sort_order asc(默认), create_time desc/asc, id asc/desc
	if req.GetOrderBy() != "" {
		switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
		case "create_time desc", "created_at desc":
			query = query.Order(lion.Desc(groups.FieldCreatedAt))
		case "create_time asc", "created_at asc":
			query = query.Order(lion.Asc(groups.FieldCreatedAt))
		case "sort_order asc":
			query = query.Order(lion.Asc(groups.FieldSortOrder), lion.Asc(groups.FieldID))
		case "sort_order desc":
			query = query.Order(lion.Desc(groups.FieldSortOrder), lion.Asc(groups.FieldID))
		case "id asc":
			query = query.Order(lion.Asc(groups.FieldID))
		case "id desc":
			query = query.Order(lion.Desc(groups.FieldID))
		default:
			query = query.Order(lion.Asc(groups.FieldSortOrder), lion.Asc(groups.FieldID))
		}
	} else {
		query = query.Order(lion.Asc(groups.FieldSortOrder), lion.Asc(groups.FieldID))
	}

	// 计算总数（分页前）
	totalSize, err := query.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	// 分页（TREE / TREE_EXPANDED 不分页，取全量）
	pageSize := GetPageSize(ctx, req.GetPageSize())
	var groupList []*lion.Groups

	switch req.GetStructure() {
	case adminv1.Structure_STRUCTURE_TREE, adminv1.Structure_STRUCTURE_TREE_EXPANDED:
		groupList, err = query.All(ctx)
		if err != nil {
			return nil, err
		}
		result.TotalSize = int32(len(groupList))
	default:
		var lastID int
		if req.GetPageToken() != "" {
			data, err := base64.StdEncoding.DecodeString(req.GetPageToken())
			if err != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token: %v", err))
			}
			if err := json.Unmarshal(data, &lastID); err != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token format: %v", err))
			}
			if lastID > 0 {
				query = query.Where(groups.IDGT(lastID))
			}
		}
		switch p := req.GetPagination().(type) {
		case *adminv1.ListGroupsRequest_Offset:
			query = query.Offset(int(p.Offset))
		case *adminv1.ListGroupsRequest_PageToken:
			// cursor 已在上面处理
		}
		query = query.Limit(int(pageSize))
		groupList, err = query.All(ctx)
		if err != nil {
			return nil, err
		}
	}

	// 根据 View 决定是否返回时间戳等字段（STANDARD/FULL 含 created_at, updated_at, deleted_at）
	includeTimestamps := req.GetView() == adminv1.View_VIEW_STANDARD || req.GetView() == adminv1.View_VIEW_FULL

	// 按 structure 输出：平铺 或 树形（Group 当前 proto 无 Children 字段，树形时返回全量平铺并按 sort_order 排序）
	switch req.GetStructure() {
	case adminv1.Structure_STRUCTURE_TREE, adminv1.Structure_STRUCTURE_TREE_EXPANDED:
		// 树形结构：返回全量平铺列表，按 sort_order、parent_id、id 排序便于前端建树
		result.Groups = make([]*adminv1.Group, 0, len(groupList))
		for _, g := range groupList {
			result.Groups = append(result.Groups, groupToProto(g, includeTimestamps))
		}
		sortGroupSlice(result.Groups)
	default:
		result.Groups = make([]*adminv1.Group, 0, len(groupList))
		for _, g := range groupList {
			result.Groups = append(result.Groups, groupToProto(g, includeTimestamps))
		}
		// cursor 分页时生成 next_page_token
		if _, ok := req.GetPagination().(*adminv1.ListGroupsRequest_PageToken); ok && len(groupList) == int(pageSize) && len(groupList) > 0 {
			last := groupList[len(groupList)-1].ID
			tokenData, _ := json.Marshal(last)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}

	return result, nil
}

// GetGroup 获取群组详情
func (a *KnownAdminAPI) GetGroup(ctx context.Context, req *adminv1.GetGroupRequest) (*adminv1.Group, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("group id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	group, err := db.Groups.Query().Select(
		groups.FieldID,
		groups.FieldCode,
		groups.FieldDisplayName,
		groups.FieldGroupType,
		groups.FieldGroupStatus,
		groups.FieldSortOrder,
		groups.FieldParentID,
		groups.FieldMaxMembers,
		groups.FieldMetadata,
		groups.FieldRefID,
		groups.FieldRefExpr,
		groups.FieldDescription,
		groups.FieldCreatedBy,
		groups.FieldUpdatedBy,
		groups.FieldCreatedAt,
		groups.FieldUpdatedAt,
		groups.FieldDeletedAt,
	).Where(
		groups.ID(int(req.Id)),
		groups.DeletedAtIsNil(),
	).Only(ctx)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("group not found")
	}

	// 详情接口默认返回完整信息（含时间戳）
	return groupToProto(group, true), nil
}

// parseListGroupsFilter 解析 filter 字符串为 predicate 列表，支持 key=value 与 AND 组合
func parseListGroupsFilter(filter string) ([]predicate.Groups, error) {
	out := make([]predicate.Groups, 0)
	parts := strings.Split(filter, " AND ")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		idx := strings.Index(p, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(strings.Trim(p[:idx], "\""))
		val := strings.TrimSpace(strings.Trim(p[idx+1:], "\""))
		switch key {
		case "status", "group_status":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("status must be int: %s", val)
			}
			out = append(out, groups.GroupStatus(n))
		case "type", "group_type":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("type must be int: %s", val)
			}
			out = append(out, groups.GroupType(n))
		case "parent_id":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("parent_id must be int: %s", val)
			}
			out = append(out, groups.ParentID(n))
		case "code":
			out = append(out, groups.CodeContainsFold(val))
		case "display_name":
			out = append(out, groups.DisplayNameContainsFold(val))
		case "ref_id":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("ref_id must be int: %s", val)
			}
			out = append(out, groups.RefID(n))
		}
	}
	return out, nil
}

func groupToProto(g *lion.Groups, includeTimestamps bool) *adminv1.Group {
	grp := &adminv1.Group{
		Id:          int64(g.ID),
		Code:        g.Code,
		Type:        adminv1.Group_Type(g.GroupType),
		Status:      adminv1.Group_Status(g.GroupStatus),
		DisplayName: g.DisplayName,
		SortOrder:   int32(g.SortOrder),
		MaxMembers:  int32(g.MaxMembers),
		Metadata:    g.Metadata,
		RefId:       int64(g.RefID),
		RefExpr:     g.RefExpr,
		Description: g.Description,
		CreatedBy:   g.CreatedBy,
		UpdatedBy:   g.UpdatedBy,
	}
	if includeTimestamps {
		grp.CreatedAt = timestamppb.New(g.CreatedAt)
		grp.UpdatedAt = timestamppb.New(g.UpdatedAt)
		if g.DeletedAt != nil {
			grp.DeletedAt = timestamppb.New(*g.DeletedAt)
		}
	}
	return grp
}

func sortGroupSlice(s []*adminv1.Group) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].SortOrder != s[j].SortOrder {
			return s[i].SortOrder < s[j].SortOrder
		}
		return s[i].Id < s[j].Id
	})
}

// UpdateGroup 更新用户组（code 创建后不建议修改，若 update_mask 含 code 仍可更新）
func (a *KnownAdminAPI) UpdateGroup(ctx context.Context, req *adminv1.UpdateGroupRequest) (*adminv1.Group, error) {
	result := &adminv1.Group{}

	if req.Group == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body group is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	group, err := db.Groups.Get(ctx, int(req.Group.Id))
	if err != nil {
		return result, err
	}

	update := group.Update()
	updatedBy := req.Group.UpdatedBy
	if updatedBy == 0 {
		if uid, err := GetUserID(ctx); err == nil {
			updatedBy = uid
		}
	}

	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		for _, field := range req.UpdateMask.Paths {
			switch field {
			case "code":
				update.SetCode(req.Group.Code)
			case "display_name":
				update.SetDisplayName(req.Group.DisplayName)
			case "type":
				// type 创建后不建议修改，但保留 update_mask 支持
				update.SetGroupType(int(req.Group.Type.Number()))
			case "status":
				update.SetGroupStatus(int(req.Group.Status.Number()))
			case "sort_order":
				update.SetSortOrder(int(req.Group.SortOrder))
			case "max_members":
				update.SetMaxMembers(int(req.Group.MaxMembers))
			case "metadata":
				update.SetMetadata(req.Group.Metadata)
			case "ref_id":
				update.SetRefID(int(req.Group.RefId))
			case "ref_expr":
				update.SetRefExpr(req.Group.RefExpr)
			case "description":
				update.SetDescription(req.Group.Description)
			case "updated_by":
				update.SetUpdatedBy(updatedBy)
			}
		}
		update.SetUpdatedBy(updatedBy)
	} else {
		displayName := req.Group.DisplayName
		if displayName == "" {
			displayName = group.DisplayName
		}
		update.
			SetCode(req.Group.Code).
			SetDisplayName(displayName).
			SetGroupType(int(req.Group.Type.Number())).
			SetGroupStatus(int(req.Group.Status.Number())).
			SetSortOrder(int(req.Group.SortOrder)).
			SetMaxMembers(int(req.Group.MaxMembers)).
			SetMetadata(req.Group.Metadata).
			SetRefID(int(req.Group.RefId)).
			SetRefExpr(req.Group.RefExpr).
			SetDescription(req.Group.Description).
			SetUpdatedBy(updatedBy)
	}

	updatedGroup, err := update.Save(ctx)
	if err != nil {
		return result, err
	}

	return groupToProto(updatedGroup, true), nil
}

// DeleteGroup 删除用户组（软删除：设置 deleted_at）
func (a *KnownAdminAPI) DeleteGroup(ctx context.Context, req *adminv1.DeleteGroupRequest) (*emptypb.Empty, error) {
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	group, err := db.Groups.Get(ctx, int(req.Id))
	if err != nil {
		return nil, err
	}

	// SYSTEM 类型群组不允许删除
	if adminv1.Group_Type(group.GroupType) == adminv1.Group_SYSTEM {
		return nil, errs.InvalidArgument(ctx).WithMessage("SYSTEM type groups cannot be deleted")
	}

	_, err = group.Update().SetDeletedAt(time.Now()).Save(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// ListGroupMembers 获取群组成员列表
// 根据群组类型从不同数据源获取成员：
//   - DEPARTMENT: 从 user_departments 表查询关联部门的成员
//   - ROLE: 从 user_roles 表查询关联角色的成员
//   - 其他类型: 从 user_groups 表查询
func (a *KnownAdminAPI) ListGroupMembers(ctx context.Context, req *adminv1.ListGroupMembersRequest) (*adminv1.ListGroupMembersResponse, error) {
	result := &adminv1.ListGroupMembersResponse{
		Members: make([]*adminv1.Membership, 0),
	}

	if req.Parent == "" {
		return result, errs.InvalidArgument(ctx).WithMessage("request body parent is empty")
	}

	groupID, err := parseGroupParent(req.Parent)
	if err != nil {
		return result, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid parent: %v", err))
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 查询群组信息以确定类型和关联ID
	group, err := db.Groups.Get(ctx, groupID)
	if err != nil {
		return result, err
	}

	groupType := adminv1.Group_Type(group.GroupType)

	// 根据群组类型路由到不同的数据源
	switch groupType {
	case adminv1.Group_DEPARTMENT:
		return a.listGroupMembersFromDepartment(ctx, req, db, group.RefID)
	case adminv1.Group_ROLE:
		return a.listGroupMembersFromRole(ctx, req, db, group.RefID)
	case adminv1.Group_DYNAMIC:
		return a.listGroupMembersFromDynamicRule(ctx, req, db, group.RefExpr)
	default:
		return a.listGroupMembersFromUserGroups(ctx, req, db, groupID)
	}
}

// listGroupMembersFromDepartment 从 user_departments 表查询部门群组成员
func (a *KnownAdminAPI) listGroupMembersFromDepartment(ctx context.Context, req *adminv1.ListGroupMembersRequest, db *lion.Client, departmentID int) (*adminv1.ListGroupMembersResponse, error) {
	result := &adminv1.ListGroupMembersResponse{
		Members: make([]*adminv1.Membership, 0),
	}

	if departmentID == 0 {
		return result, nil
	}

	memberQuery := db.UserDepartments.Query().Where(userdepartments.DepartmentIDEQ(departmentID))

	// 排序
	switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
	case "created_at desc", "create_time desc":
		memberQuery = memberQuery.Order(lion.Desc(userdepartments.FieldCreatedAt))
	case "created_at asc", "create_time asc":
		memberQuery = memberQuery.Order(lion.Asc(userdepartments.FieldCreatedAt))
	default:
		memberQuery = memberQuery.Order(lion.Desc(userdepartments.FieldID))
	}

	totalSize, err := memberQuery.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	pageSize := GetPageSize(ctx, req.GetPageSize())

	// 分页
	switch p := req.GetPagination().(type) {
	case *adminv1.ListGroupMembersRequest_Offset:
		memberQuery = memberQuery.Offset(int(p.Offset))
	case *adminv1.ListGroupMembersRequest_PageToken:
		if req.GetPageToken() != "" {
			data, decErr := base64.StdEncoding.DecodeString(req.GetPageToken())
			if decErr != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token: %v", decErr))
			}
			var lastID int
			if jsonErr := json.Unmarshal(data, &lastID); jsonErr != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token format: %v", jsonErr))
			}
			if lastID > 0 {
				memberQuery = memberQuery.Where(userdepartments.IDGT(lastID))
			}
		}
	}
	memberQuery = memberQuery.Limit(int(pageSize))

	members, err := memberQuery.Select(
		userdepartments.FieldID,
		userdepartments.FieldUserID,
		userdepartments.FieldDepartmentID,
		userdepartments.FieldMemberRole,
		userdepartments.FieldMemberStatus,
		userdepartments.FieldMemberType,
		userdepartments.FieldDescription,
		userdepartments.FieldMetadata,
		userdepartments.FieldCreatedBy,
		userdepartments.FieldUpdatedBy,
		userdepartments.FieldCreatedAt,
		userdepartments.FieldUpdatedAt,
	).WithLionUsers(func(q *lion.UsersQuery) {
		q.Select(users.FieldID, users.FieldUsername, users.FieldNickname)
	}).All(ctx)
	if err != nil {
		return nil, err
	}

	for _, m := range members {
		user := m.Edges.LionUsers
		if user == nil {
			continue
		}
		pm := &adminv1.Membership{
			Id:           int64(m.ID),
			UserId:       int64(m.UserID),
			Username:     user.Username,
			Nickname:     user.Nickname,
			TargetType:   adminv1.Membership_DEPARTMENT,
			TargetId:     int64(m.DepartmentID),
			MemberRole:   adminv1.Membership_Role(m.MemberRole),
			MemberStatus: adminv1.Membership_Status(m.MemberStatus),
			MemberType:   adminv1.Membership_MemberType(m.MemberType),
			Description:  m.Description,
			CreatedBy:    m.CreatedBy,
			UpdatedBy:    m.UpdatedBy,
			CreatedAt:    timestamppb.New(m.CreatedAt),
			UpdatedAt:    timestamppb.New(m.UpdatedAt),
		}
		if m.Metadata != "" {
			pm.Metadata = MetadataParse(m.Metadata)
		}
		result.Members = append(result.Members, pm)
	}

	// Cursor 分页
	if _, ok := req.GetPagination().(*adminv1.ListGroupMembersRequest_PageToken); ok && len(members) == int(pageSize) && len(members) > 0 {
		lastID := members[len(members)-1].ID
		tokenData, _ := json.Marshal(lastID)
		result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
	}

	return result, nil
}

// listGroupMembersFromRole 从 user_roles 表查询角色群组成员
func (a *KnownAdminAPI) listGroupMembersFromRole(ctx context.Context, req *adminv1.ListGroupMembersRequest, db *lion.Client, roleID int) (*adminv1.ListGroupMembersResponse, error) {
	result := &adminv1.ListGroupMembersResponse{
		Members: make([]*adminv1.Membership, 0),
	}

	if roleID == 0 {
		return result, nil
	}

	memberQuery := db.UserRoles.Query().Where(userroles.RoleIDEQ(roleID))

	// 排序
	switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
	case "created_at desc", "create_time desc":
		memberQuery = memberQuery.Order(lion.Desc(userroles.FieldCreatedAt))
	case "created_at asc", "create_time asc":
		memberQuery = memberQuery.Order(lion.Asc(userroles.FieldCreatedAt))
	default:
		memberQuery = memberQuery.Order(lion.Desc(userroles.FieldID))
	}

	totalSize, err := memberQuery.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	pageSize := GetPageSize(ctx, req.GetPageSize())

	// 分页
	switch p := req.GetPagination().(type) {
	case *adminv1.ListGroupMembersRequest_Offset:
		memberQuery = memberQuery.Offset(int(p.Offset))
	case *adminv1.ListGroupMembersRequest_PageToken:
		if req.GetPageToken() != "" {
			data, decErr := base64.StdEncoding.DecodeString(req.GetPageToken())
			if decErr != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token: %v", decErr))
			}
			var lastID int
			if jsonErr := json.Unmarshal(data, &lastID); jsonErr != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token format: %v", jsonErr))
			}
			if lastID > 0 {
				memberQuery = memberQuery.Where(userroles.IDGT(lastID))
			}
		}
	}
	memberQuery = memberQuery.Limit(int(pageSize))

	members, err := memberQuery.Select(
		userroles.FieldID,
		userroles.FieldUserID,
		userroles.FieldRoleID,
		userroles.FieldCreatedBy,
		userroles.FieldUpdatedBy,
		userroles.FieldCreatedAt,
		userroles.FieldUpdatedAt,
	).WithLionUsers(func(q *lion.UsersQuery) {
		q.Select(users.FieldID, users.FieldUsername, users.FieldNickname)
	}).All(ctx)
	if err != nil {
		return nil, err
	}

	for _, m := range members {
		user := m.Edges.LionUsers
		if user == nil {
			continue
		}
		pm := &adminv1.Membership{
			Id:         int64(m.ID),
			UserId:     int64(m.UserID),
			Username:   user.Username,
			Nickname:   user.Nickname,
			TargetType: adminv1.Membership_GROUP,
			TargetId:   int64(m.RoleID),
			MemberRole: adminv1.Membership_MEMBER,
			CreatedBy:  m.CreatedBy,
			UpdatedBy:  m.UpdatedBy,
			CreatedAt:  timestamppb.New(m.CreatedAt),
			UpdatedAt:  timestamppb.New(m.UpdatedAt),
		}
		result.Members = append(result.Members, pm)
	}

	// Cursor 分页
	if _, ok := req.GetPagination().(*adminv1.ListGroupMembersRequest_PageToken); ok && len(members) == int(pageSize) && len(members) > 0 {
		lastID := members[len(members)-1].ID
		tokenData, _ := json.Marshal(lastID)
		result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
	}

	return result, nil
}

// dynamicRuleAllowedFields 动态规则允许过滤的用户字段白名单（非敏感、非加密字段）
var dynamicRuleAllowedFields = map[string]string{
	"user_type":              "int",
	"user_status":            "int",
	"gender":                 "int",
	"email_verified":         "bool",
	"phone_number_verified":  "bool",
	"timezone":               "string",
	"locale":                 "string",
}

// listGroupMembersFromDynamicRule 根据动态规则表达式从 users 表查询成员
func (a *KnownAdminAPI) listGroupMembersFromDynamicRule(ctx context.Context, req *adminv1.ListGroupMembersRequest, db *lion.Client, memberRule string) (*adminv1.ListGroupMembersResponse, error) {
	result := &adminv1.ListGroupMembersResponse{
		Members: make([]*adminv1.Membership, 0),
	}

	if memberRule == "" {
		return result, nil
	}

	// 解析规则表达式为 ent predicates
	predicates, err := parseDynamicRule(memberRule)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage(fmt.Sprintf("invalid member_rule: %v", err))
	}

	// 默认排除已删除的用户
	predicates = append(predicates, users.DeletedAtIsNil())

	query := db.Users.Query().Where(predicates...)

	// 排序
	switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
	case "created_at desc", "create_time desc":
		query = query.Order(lion.Desc(users.FieldCreatedAt))
	case "created_at asc", "create_time asc":
		query = query.Order(lion.Asc(users.FieldCreatedAt))
	default:
		query = query.Order(lion.Asc(users.FieldID))
	}

	totalSize, err := query.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	pageSize := GetPageSize(ctx, req.GetPageSize())

	// 分页
	switch p := req.GetPagination().(type) {
	case *adminv1.ListGroupMembersRequest_Offset:
		query = query.Offset(int(p.Offset))
	case *adminv1.ListGroupMembersRequest_PageToken:
		if req.GetPageToken() != "" {
			data, decErr := base64.StdEncoding.DecodeString(req.GetPageToken())
			if decErr != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token: %v", decErr))
			}
			var lastID int
			if jsonErr := json.Unmarshal(data, &lastID); jsonErr != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token format: %v", jsonErr))
			}
			if lastID > 0 {
				query = query.Where(users.IDGT(lastID))
			}
		}
	}
	query = query.Limit(int(pageSize))

	userList, err := query.Select(
		users.FieldID,
		users.FieldUsername,
		users.FieldNickname,
	).All(ctx)
	if err != nil {
		return nil, err
	}

	// 转换为虚拟成员关系
	for _, u := range userList {
		result.Members = append(result.Members, &adminv1.Membership{
			UserId:     int64(u.ID),
			Username:   u.Username,
			Nickname:   u.Nickname,
			TargetType: adminv1.Membership_GROUP,
			MemberRole: adminv1.Membership_MEMBER,
		})
	}

	// Cursor 分页
	if _, ok := req.GetPagination().(*adminv1.ListGroupMembersRequest_PageToken); ok && len(userList) == int(pageSize) && len(userList) > 0 {
		lastID := userList[len(userList)-1].ID
		tokenData, _ := json.Marshal(lastID)
		result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
	}

	return result, nil
}

// parseDynamicRule 解析动态规则表达式为 ent predicates
// 格式: "field op value AND field op value ..."
// 支持操作符: =, !=, >, >=, <, <=
func parseDynamicRule(rule string) ([]predicate.Users, error) {
	var predicates []predicate.Users
	parts := strings.Split(rule, " AND ")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pred, err := parseDynamicRuleCondition(p)
		if err != nil {
			return nil, err
		}
		predicates = append(predicates, pred)
	}
	if len(predicates) == 0 {
		return nil, fmt.Errorf("empty rule")
	}
	return predicates, nil
}

// parseDynamicRuleCondition 解析单个条件表达式
func parseDynamicRuleCondition(cond string) (predicate.Users, error) {
	// 支持 >=, <=, !=, >, <, = 操作符
	operators := []string{">=", "<=", "!=", ">", "<", "="}
	var fieldName, op, val string
	for _, operator := range operators {
		idx := strings.Index(cond, operator)
		if idx > 0 {
			fieldName = strings.TrimSpace(cond[:idx])
			op = operator
			val = strings.TrimSpace(cond[idx+len(operator):])
			break
		}
	}
	if fieldName == "" || op == "" {
		return nil, fmt.Errorf("invalid condition: %s", cond)
	}

	// 去掉值的引号
	val = strings.Trim(val, "'\"")

	// 校验字段在白名单中
	fieldType, ok := dynamicRuleAllowedFields[fieldName]
	if !ok {
		return nil, fmt.Errorf("field %q is not allowed in dynamic rule", fieldName)
	}

	switch fieldType {
	case "int":
		n, err := strconv.Atoi(val)
		if err != nil {
			return nil, fmt.Errorf("field %q expects int value, got %q", fieldName, val)
		}
		return dynamicRuleIntPredicate(fieldName, op, n)
	case "bool":
		b, err := strconv.ParseBool(val)
		if err != nil {
			return nil, fmt.Errorf("field %q expects bool value, got %q", fieldName, val)
		}
		return dynamicRuleBoolPredicate(fieldName, op, b)
	case "string":
		return dynamicRuleStringPredicate(fieldName, op, val)
	default:
		return nil, fmt.Errorf("unsupported field type %q for field %q", fieldType, fieldName)
	}
}

// dynamicRuleIntPredicate 构建 int 类型字段的 predicate
func dynamicRuleIntPredicate(fieldName, op string, val int) (predicate.Users, error) {
	switch fieldName {
	case "user_type":
		switch op {
		case "=":
			return users.UserTypeEQ(val), nil
		case "!=":
			return users.UserTypeNEQ(val), nil
		case ">":
			return users.UserTypeGT(val), nil
		case ">=":
			return users.UserTypeGTE(val), nil
		case "<":
			return users.UserTypeLT(val), nil
		case "<=":
			return users.UserTypeLTE(val), nil
		}
	case "user_status":
		switch op {
		case "=":
			return users.UserStatusEQ(val), nil
		case "!=":
			return users.UserStatusNEQ(val), nil
		case ">":
			return users.UserStatusGT(val), nil
		case ">=":
			return users.UserStatusGTE(val), nil
		case "<":
			return users.UserStatusLT(val), nil
		case "<=":
			return users.UserStatusLTE(val), nil
		}
	case "gender":
		switch op {
		case "=":
			return users.GenderEQ(val), nil
		case "!=":
			return users.GenderNEQ(val), nil
		}
	}
	return nil, fmt.Errorf("unsupported operator %q for field %q", op, fieldName)
}

// dynamicRuleBoolPredicate 构建 bool 类型字段的 predicate
func dynamicRuleBoolPredicate(fieldName, op string, val bool) (predicate.Users, error) {
	if op != "=" && op != "!=" {
		return nil, fmt.Errorf("bool field %q only supports = and != operators", fieldName)
	}
	target := val
	if op == "!=" {
		target = !val
	}
	switch fieldName {
	case "email_verified":
		return users.EmailVerifiedEQ(target), nil
	case "phone_number_verified":
		return users.PhoneNumberVerifiedEQ(target), nil
	}
	return nil, fmt.Errorf("unsupported bool field %q", fieldName)
}

// dynamicRuleStringPredicate 构建 string 类型字段的 predicate
func dynamicRuleStringPredicate(fieldName, op string, val string) (predicate.Users, error) {
	switch fieldName {
	case "timezone":
		switch op {
		case "=":
			return users.TimezoneEQ(val), nil
		case "!=":
			return users.TimezoneNEQ(val), nil
		}
	case "locale":
		switch op {
		case "=":
			return users.LocaleEQ(val), nil
		case "!=":
			return users.LocaleNEQ(val), nil
		}
	}
	return nil, fmt.Errorf("unsupported operator %q for string field %q", op, fieldName)
}

// listGroupMembersFromUserGroups 从 user_groups 表查询普通群组成员（默认方式）
func (a *KnownAdminAPI) listGroupMembersFromUserGroups(ctx context.Context, req *adminv1.ListGroupMembersRequest, db *lion.Client, groupID int) (*adminv1.ListGroupMembersResponse, error) {
	result := &adminv1.ListGroupMembersResponse{
		Members: make([]*adminv1.Membership, 0),
	}

	where := []predicate.UserGroups{usergroups.GroupIDEQ(groupID)}
	if req.GetFilter() != "" {
		filterPredicates, err := parseListGroupMembersFilter(req.GetFilter())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid filter: %v", err))
		}
		where = append(where, filterPredicates...)
	}

	query := db.UserGroups.Query().Where(where...)

	if req.GetOrderBy() != "" {
		switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
		case "joined_at desc":
			query = query.Order(lion.Desc(usergroups.FieldJoinedAt), lion.Asc(usergroups.FieldID))
		case "joined_at asc":
			query = query.Order(lion.Asc(usergroups.FieldJoinedAt), lion.Asc(usergroups.FieldID))
		case "create_time desc", "created_at desc":
			query = query.Order(lion.Desc(usergroups.FieldCreatedAt), lion.Asc(usergroups.FieldID))
		case "create_time asc", "created_at asc":
			query = query.Order(lion.Asc(usergroups.FieldCreatedAt), lion.Asc(usergroups.FieldID))
		default:
			query = query.Order(lion.Desc(usergroups.FieldCreatedAt), lion.Asc(usergroups.FieldID))
		}
	} else {
		query = query.Order(lion.Desc(usergroups.FieldCreatedAt), lion.Asc(usergroups.FieldID))
	}

	totalSize, err := query.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	pageSize := GetPageSize(ctx, req.GetPageSize())
	var lastID int
	if req.GetPageToken() != "" {
		data, err := base64.StdEncoding.DecodeString(req.GetPageToken())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token: %v", err))
		}
		if err := json.Unmarshal(data, &lastID); err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token format: %v", err))
		}
		if lastID > 0 {
			query = query.Where(usergroups.IDGT(lastID))
		}
	}
	switch p := req.GetPagination().(type) {
	case *adminv1.ListGroupMembersRequest_Offset:
		query = query.Offset(int(p.Offset))
	case *adminv1.ListGroupMembersRequest_PageToken:
		// cursor 已处理
	}
	query = query.Limit(int(pageSize))

	members, err := query.Select(
		usergroups.FieldID,
		usergroups.FieldUserID,
		usergroups.FieldGroupID,
		usergroups.FieldMemberRole,
		usergroups.FieldMemberStatus,
		usergroups.FieldJoinedAt,
		usergroups.FieldExpiredAt,
		usergroups.FieldMetadata,
		usergroups.FieldDescription,
		usergroups.FieldCreatedBy,
		usergroups.FieldUpdatedBy,
		usergroups.FieldCreatedAt,
		usergroups.FieldUpdatedAt,
	).WithLionUsers(func(q *lion.UsersQuery) {
		q.Select(users.FieldID, users.FieldUsername, users.FieldNickname)
	}).All(ctx)
	if err != nil {
		return nil, err
	}

	for _, member := range members {
		result.Members = append(result.Members, userGroupToProto(member))
	}

	if _, ok := req.GetPagination().(*adminv1.ListGroupMembersRequest_PageToken); ok && len(members) == int(pageSize) && len(members) > 0 {
		last := members[len(members)-1].ID
		tokenData, _ := json.Marshal(last)
		result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
	}

	return result, nil
}

// parseListGroupMembersFilter 解析 filter，支持 member_status=2, member_role=3
func parseListGroupMembersFilter(filter string) ([]predicate.UserGroups, error) {
	var out []predicate.UserGroups
	parts := strings.Split(filter, " AND ")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		idx := strings.Index(p, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(strings.Trim(p[:idx], "\""))
		val := strings.TrimSpace(strings.Trim(p[idx+1:], "\""))
		switch key {
		case "member_status", "status":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("member_status must be int: %s", val)
			}
			out = append(out, usergroups.MemberStatusEQ(n))
		case "member_role", "role":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("member_role must be int: %s", val)
			}
			out = append(out, usergroups.MemberRoleEQ(n))
		}
	}
	return out, nil
}

// userGroupToProto 将 *lion.UserGroups 转为 *adminv1.Membership（含 Metadata）
func userGroupToProto(member *lion.UserGroups) *adminv1.Membership {
	gm := &adminv1.Membership{
		Id:           int64(member.ID),
		UserId:       int64(member.UserID),
		TargetType:   adminv1.Membership_GROUP,
		TargetId:     int64(member.GroupID),
		MemberRole:   adminv1.Membership_Role(member.MemberRole),
		MemberStatus: adminv1.Membership_Status(member.MemberStatus),
		JoinedAt:     timestamppb.New(member.JoinedAt),
		CreatedBy:    member.CreatedBy,
		UpdatedBy:    member.UpdatedBy,
		CreatedAt:    timestamppb.New(member.CreatedAt),
		UpdatedAt:    timestamppb.New(member.UpdatedAt),
		Description:  member.Description,
		Metadata:     member.Metadata,
	}
	if member.Edges.LionUsers != nil {
		gm.Username = member.Edges.LionUsers.Username
		gm.Nickname = member.Edges.LionUsers.Nickname
	}
	if !member.ExpiredAt.IsZero() {
		gm.ExpiredAt = timestamppb.New(member.ExpiredAt)
	}
	return gm
}

// CreateGroupMembers 创建群组成员
func (a *KnownAdminAPI) CreateGroupMembers(ctx context.Context, req *adminv1.CreateGroupMembersRequest) (*adminv1.CreateGroupMembersResponse, error) {
	result := &adminv1.CreateGroupMembersResponse{}

	if req.Parent == "" {
		return result, errs.InvalidArgument(ctx).WithMessage("request body parent is empty")
	}

	userID, err := GetUserID(ctx)
	if err != nil {
		return result, err
	}

	groupID, err := parseGroupParent(req.Parent)
	if err != nil {
		return result, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid parent: %v", err))
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 校验群组类型：DEPARTMENT/ROLE 类型不允许手动添加成员
	groupType, err := a.getGroupType(ctx, db, groupID)
	if err != nil {
		return result, err
	}
	if isAutoManagedGroupType(groupType) {
		typeName := groupType.String()
		return result, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("%s type groups do not support manual member management, members are synced automatically", typeName))
	}

	allMembers := make([]*lion.UserGroupsCreate, 0, len(req.Members))

	for _, member := range req.Members {
		create := db.UserGroups.Create().
			SetUserID(int(member.UserId)).
			SetGroupID(groupID).
			SetMemberRole(int(member.MemberRole)).
			SetMemberStatus(int(member.MemberStatus)).
			SetCreatedBy(userID).
			SetUpdatedBy(userID).
			SetDescription(member.Description)

		joinedAt := time.Now()
		if member.JoinedAt != nil {
			joinedAt = member.JoinedAt.AsTime()
		}
		create = create.SetJoinedAt(joinedAt)

		if member.ExpiredAt != nil && !member.ExpiredAt.AsTime().IsZero() {
			create = create.SetExpiredAt(member.ExpiredAt.AsTime())
		}
		if len(member.Metadata) > 0 {
			create = create.SetMetadata(member.Metadata)
		}

		allMembers = append(allMembers, create)
	}

	_, err = db.UserGroups.CreateBulk(allMembers...).Save(ctx)
	if err != nil {
		return result, err
	}

	return result, nil
}

// DeleteGroupMember 删除群组成员
func (a *KnownAdminAPI) DeleteGroupMember(ctx context.Context, req *adminv1.DeleteGroupMemberRequest) (*emptypb.Empty, error) {
	groupID, err := parseGroupParent(req.Parent)
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid parent: %v", err))
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 校验群组类型：DEPARTMENT/ROLE 类型不允许手动删除成员
	groupType, err := a.getGroupType(ctx, db, groupID)
	if err != nil {
		return nil, err
	}
	if isAutoManagedGroupType(groupType) {
		typeName := groupType.String()
		return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("%s type groups do not support manual member management, members are synced automatically", typeName))
	}

	_, err = db.UserGroups.Delete().
		Where(
			usergroups.GroupIDEQ(groupID),
			usergroups.UserIDEQ(int(req.UserId)),
		).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// UpdateGroupMember 更新群组成员
func (a *KnownAdminAPI) UpdateGroupMember(ctx context.Context, req *adminv1.UpdateGroupMemberRequest) (*adminv1.Membership, error) {
	result := &adminv1.Membership{}

	if req.Parent == "" {
		return result, errs.InvalidArgument(ctx).WithMessage("request body parent is empty")
	}
	if req.Member == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body member is nil")
	}

	userID, err := GetUserID(ctx)
	if err != nil {
		return result, err
	}

	groupID, err := parseGroupParent(req.Parent)
	if err != nil {
		return result, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid parent: %v", err))
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 校验群组类型：DEPARTMENT/ROLE 类型不允许手动编辑成员
	groupType, err := a.getGroupType(ctx, db, groupID)
	if err != nil {
		return result, err
	}
	if isAutoManagedGroupType(groupType) {
		typeName := groupType.String()
		return result, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("%s type groups do not support manual member management, members are synced automatically", typeName))
	}

	member, err := db.UserGroups.Query().
		Where(
			usergroups.GroupIDEQ(groupID),
			usergroups.UserIDEQ(int(req.UserId)),
		).
		WithLionUsers(func(q *lion.UsersQuery) {
			q.Select(users.FieldID, users.FieldUsername, users.FieldNickname)
		}).
		Only(ctx)
	if err != nil {
		return result, err
	}

	update := member.Update().SetUpdatedBy(userID).SetUpdatedAt(time.Now())

	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		for _, field := range req.UpdateMask.Paths {
			switch field {
			case "member_role":
				update.SetMemberRole(int(req.Member.MemberRole))
			case "member_status":
				update.SetMemberStatus(int(req.Member.MemberStatus))
			case "description":
				update.SetDescription(req.Member.Description)
			case "expired_at":
				if req.Member.ExpiredAt != nil {
					update.SetExpiredAt(req.Member.ExpiredAt.AsTime())
				}
			case "metadata":
				if len(req.Member.Metadata) > 0 {
					update.SetMetadata(req.Member.Metadata)
				}
			}
		}
	} else {
		update.
			SetMemberRole(int(req.Member.MemberRole)).
			SetMemberStatus(int(req.Member.MemberStatus)).
			SetDescription(req.Member.Description)
		if req.Member.ExpiredAt != nil {
			update.SetExpiredAt(req.Member.ExpiredAt.AsTime())
		}
		if len(req.Member.Metadata) > 0 {
			update.SetMetadata(req.Member.Metadata)
		}
	}

	updated, err := update.Save(ctx)
	if err != nil {
		return result, err
	}

	// 重新加载以包含 Edges（WithLionUsers）
	updated, err = db.UserGroups.Query().
		Where(usergroups.IDEQ(updated.ID)).
		WithLionUsers(func(q *lion.UsersQuery) {
			q.Select(users.FieldID, users.FieldUsername, users.FieldNickname)
		}).
		Only(ctx)
	if err != nil {
		return userGroupToProto(updated), nil
	}

	return userGroupToProto(updated), nil
}
