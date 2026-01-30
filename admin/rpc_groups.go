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
	"github.com/grpc-kit/pkg/lion/usergroups"
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
	if strings.HasPrefix(parent, "groups/") {
		parent = strings.TrimPrefix(parent, "groups/")
	}
	return strconv.Atoi(strings.TrimSpace(parent))
}

// CreateGroup 创建用户组
func (a *KnownAdminAPI) CreateGroup(ctx context.Context, req *adminv1.CreateGroupRequest) (*adminv1.Group, error) {
	result := &adminv1.Group{}

	if req.Group == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body group is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	departmentID := int(req.Group.DepartmentId)
	if departmentID == 0 {
		departmentID = 1
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

	group, err := db.Groups.Create().
		SetCode(req.Group.Code).
		SetDisplayName(displayName).
		SetGroupType(int(req.Group.Type.Number())).
		SetGroupStatus(int(req.Group.Status.Number())).
		SetSortOrder(int(req.Group.SortOrder)).
		SetParentID(int(req.Group.ParentId)).
		SetMaxMembers(int(req.Group.MaxMembers)).
		SetMetadata(req.Group.Metadata).
		SetExternalID(req.Group.ExternalId).
		SetDepartmentID(departmentID).
		SetDescription(req.Group.Description).
		SetCreatedBy(createdBy).
		SetUpdatedBy(updatedBy).
		Save(ctx)
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

	// filter: 简单 AIP-160 风格解析，支持 status=2, type=1, parent_id=0, code=xxx, department_id=123
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

	// 排序 order_by: create_time desc/asc, sort_order asc/desc, id asc/desc
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
			query = query.Order(lion.Desc(groups.FieldCreatedAt))
		}
	} else {
		query = query.Order(lion.Desc(groups.FieldCreatedAt))
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
	case adminv1.Structure_TREE, adminv1.Structure_TREE_EXPANDED:
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
	includeTimestamps := req.GetView() == adminv1.View_STANDARD || req.GetView() == adminv1.View_FULL

	// 按 structure 输出：平铺 或 树形（Group 当前 proto 无 Children 字段，树形时返回全量平铺并按 sort_order 排序）
	switch req.GetStructure() {
	case adminv1.Structure_TREE, adminv1.Structure_TREE_EXPANDED:
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
			out = append(out, groups.CodeEQ(val))
		case "department_id":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("department_id must be int: %s", val)
			}
			out = append(out, groups.DepartmentID(n))
		}
	}
	return out, nil
}

func groupToProto(g *lion.Groups, includeTimestamps bool) *adminv1.Group {
	grp := &adminv1.Group{
		Id:           int32(g.ID),
		Code:         g.Code,
		Type:         adminv1.Group_Type(g.GroupType),
		Status:       adminv1.Group_Status(g.GroupStatus),
		DisplayName:  g.DisplayName,
		SortOrder:    int32(g.SortOrder),
		ParentId:     int32(g.ParentID),
		MaxMembers:   int32(g.MaxMembers),
		Metadata:     g.Metadata,
		ExternalId:   g.ExternalID,
		DepartmentId: int32(g.DepartmentID),
		Description:  g.Description,
		CreatedBy:    g.CreatedBy,
		UpdatedBy:    g.UpdatedBy,
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
				update.SetGroupType(int(req.Group.Type.Number()))
			case "status":
				update.SetGroupStatus(int(req.Group.Status.Number()))
			case "sort_order":
				update.SetSortOrder(int(req.Group.SortOrder))
			case "parent_id":
				update.SetParentID(int(req.Group.ParentId))
			case "max_members":
				update.SetMaxMembers(int(req.Group.MaxMembers))
			case "metadata":
				update.SetMetadata(req.Group.Metadata)
			case "external_id":
				update.SetExternalID(req.Group.ExternalId)
			case "department_id":
				update.SetDepartmentID(int(req.Group.DepartmentId))
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
			SetParentID(int(req.Group.ParentId)).
			SetMaxMembers(int(req.Group.MaxMembers)).
			SetMetadata(req.Group.Metadata).
			SetExternalID(req.Group.ExternalId).
			SetDepartmentID(int(req.Group.DepartmentId)).
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

	_, err = group.Update().SetDeletedAt(time.Now()).Save(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// ListGroupMembers 获取群组成员列表
func (a *KnownAdminAPI) ListGroupMembers(ctx context.Context, req *adminv1.ListGroupMembersRequest) (*adminv1.ListGroupMembersResponse, error) {
	result := &adminv1.ListGroupMembersResponse{
		GroupMembers: make([]*adminv1.GroupMember, 0),
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
		result.GroupMembers = append(result.GroupMembers, userGroupToProto(member))
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

// userGroupToProto 将 *lion.UserGroups 转为 *adminv1.GroupMember（含 Metadata）
func userGroupToProto(member *lion.UserGroups) *adminv1.GroupMember {
	gm := &adminv1.GroupMember{
		Id:           int32(member.ID),
		UserId:       int64(member.UserID),
		GroupId:      int32(member.GroupID),
		MemberRole:   adminv1.GroupMember_Role(member.MemberRole),
		MemberStatus: adminv1.GroupMember_Status(member.MemberStatus),
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

	allMembers := make([]*lion.UserGroupsCreate, 0, len(req.GroupMembers))

	for _, member := range req.GroupMembers {
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
func (a *KnownAdminAPI) UpdateGroupMember(ctx context.Context, req *adminv1.UpdateGroupMemberRequest) (*adminv1.GroupMember, error) {
	result := &adminv1.GroupMember{}

	if req.Parent == "" {
		return result, errs.InvalidArgument(ctx).WithMessage("request body parent is empty")
	}
	if req.GroupMember == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body group_member is nil")
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
				update.SetMemberRole(int(req.GroupMember.MemberRole))
			case "member_status":
				update.SetMemberStatus(int(req.GroupMember.MemberStatus))
			case "description":
				update.SetDescription(req.GroupMember.Description)
			case "expired_at":
				if req.GroupMember.ExpiredAt != nil {
					update.SetExpiredAt(req.GroupMember.ExpiredAt.AsTime())
				}
			case "metadata":
				if len(req.GroupMember.Metadata) > 0 {
					update.SetMetadata(req.GroupMember.Metadata)
				}
			}
		}
	} else {
		update.
			SetMemberRole(int(req.GroupMember.MemberRole)).
			SetMemberStatus(int(req.GroupMember.MemberStatus)).
			SetDescription(req.GroupMember.Description)
		if req.GroupMember.ExpiredAt != nil {
			update.SetExpiredAt(req.GroupMember.ExpiredAt.AsTime())
		}
		if len(req.GroupMember.Metadata) > 0 {
			update.SetMetadata(req.GroupMember.Metadata)
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
