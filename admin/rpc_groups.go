package admin

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion/schema"
	"github.com/grpc-kit/pkg/lion/usermemberships"
	"github.com/grpc-kit/pkg/lion/users"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/groups"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/roles"
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
	group, err := db.Groups.Query().Where(groups.IDEQ(groupID), groups.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		return adminv1.Group_TYPE_UNSPECIFIED, err
	}
	if _, err := groupToProto(group, false); err != nil {
		return adminv1.Group_TYPE_UNSPECIFIED, errs.FailedPrecondition(ctx).WithMessage(err.Error())
	}
	return adminv1.Group_Type(group.GroupType), nil
}

// isAutoManagedGroupType 判断群组类型是否为自动管理成员类型（不允许手动添加/删除/编辑成员）
// DEPARTMENT(1), ROLE(2), DYNAMIC(3), SYSTEM(4) 的成员均由系统自动管理
func isAutoManagedGroupType(t adminv1.Group_Type) bool {
	return t == adminv1.Group_DEPARTMENT || t == adminv1.Group_ROLE || t == adminv1.Group_DYNAMIC || t == adminv1.Group_SYSTEM
}

// CreateGroup 创建用户组
func (a *KnownAdminAPI) CreateGroup(ctx context.Context, req *adminv1.CreateGroupRequest) (*adminv1.Group, error) {
	result := &adminv1.Group{}

	if req.Group == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body group is nil")
	}
	if req.Group.Protected {
		return result, errs.InvalidArgument(ctx).WithMessage("protected field is managed by system")
	}

	groupType := req.Group.Type

	code, err := schema.EnsureCode(req.Group.Code)
	if err != nil {
		return result, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	req.Group.Code = code
	if code == "everyone" {
		return result, errs.InvalidArgument(ctx).WithMessage("group code is reserved for a built-in group")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	validated, err := validateGroupTypeConfig(ctx, tx.Client(), req.Group, false)
	if err != nil {
		return result, groupConfigWriteError(ctx, err)
	}
	if groupType == adminv1.Group_DYNAMIC && req.Group.Status == adminv1.Group_ACTIVE {
		if err := lockAndCheckActiveRuleGroupCapacity(ctx, tx, 1); err != nil {
			return nil, err
		}
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

	create := tx.Groups.Create().
		SetCode(req.Group.Code).
		SetDisplayName(displayName).
		SetGroupType(int(groupType.Number())).
		SetGroupStatus(int(req.Group.Status.Number())).
		SetSortOrder(int(req.Group.SortOrder)).
		SetParentID(0).
		SetMaxMembers(int(req.Group.MaxMembers)).
		SetMetadata(req.Group.Metadata).
		SetVisibility(int(req.Group.Visibility.Number())).
		SetProtected(false).
		SetDescription(req.Group.Description).
		SetCreatedBy(createdBy).
		SetUpdatedBy(updatedBy).
		SetNillableSourceID(validated.sourceID)
	if len(validated.config) > 0 {
		create.SetConfig(validated.config)
	}

	group, err := create.Save(ctx)
	if err != nil {
		if lion.IsConstraintError(err) {
			return result, errs.AlreadyExists(ctx).WithMessage("group code or source mapping already exists, including recycle-bin rows")
		}
		return result, err
	}
	resultGroup, err := groupToProto(group, true)
	if err != nil {
		return nil, errs.FailedPrecondition(ctx).WithMessage(err.Error())
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return resultGroup, nil
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
	if req.GetGroupType() > 0 {
		where = append(where, groups.GroupType(int(req.GetGroupType())))
	}
	if req.GetGroupStatus() > 0 {
		where = append(where, groups.GroupStatus(int(req.GetGroupStatus())))
	}
	if code := strings.TrimSpace(req.GetCode()); code != "" {
		where = append(where, groups.CodeContainsFold(code))
	}
	if displayName := strings.TrimSpace(req.GetDisplayName()); displayName != "" {
		where = append(where, groups.DisplayNameContainsFold(displayName))
	}
	if req.GetFilter() != "" {
		predicates, deletedOnly, err := parseListGroupsFilter(req.GetFilter())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid filter: %v", err))
		}
		if deletedOnly && !req.GetShowDeleted() {
			return nil, errs.InvalidArgument(ctx).WithMessage("deleted_at filter requires show_deleted=true")
		}
		where = append(where, predicates...)
		if deletedOnly {
			where = append(where, groups.DeletedAtNotNil())
		}
	}

	groupQuery := db.Groups.Query()
	if !req.GetShowDeleted() {
		groupQuery = groupQuery.Where(groups.DeletedAtIsNil())
	}
	if len(where) > 0 {
		groupQuery = groupQuery.Where(where...)
	}

	_, cursorMode := req.GetPagination().(*adminv1.ListGroupsRequest_PageToken)
	if cursorMode {
		if err := requireIDCursorOrder(ctx, req.GetOrderBy()); err != nil {
			return nil, err
		}
		groupQuery = groupQuery.Order(lion.Asc(groups.FieldID))
	} else {
		switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
		case "created_at asc", "create_time asc":
			groupQuery = groupQuery.Order(lion.Asc(groups.FieldCreatedAt), lion.Asc(groups.FieldID))
		case "created_at desc", "create_time desc":
			groupQuery = groupQuery.Order(lion.Desc(groups.FieldCreatedAt), lion.Desc(groups.FieldID))
		default:
			groupQuery = groupQuery.Order(lion.Asc(groups.FieldSortOrder), lion.Asc(groups.FieldID))
		}
	}

	totalSize, err := groupQuery.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	pageSize := GetPageSize(ctx, req.GetPageSize())
	switch p := req.GetPagination().(type) {
	case *adminv1.ListGroupsRequest_Offset:
		groupQuery = groupQuery.Offset(int(p.Offset))
	case *adminv1.ListGroupsRequest_PageToken:
		lastID, tokenErr := decodeGroupIDPageToken(ctx, p.PageToken)
		if tokenErr != nil {
			return nil, tokenErr
		}
		if lastID > 0 {
			groupQuery = groupQuery.Where(groups.IDGT(lastID))
		}
	}

	groupList, err := groupQuery.Limit(int(pageSize)).All(ctx)
	if err != nil {
		return nil, err
	}

	includeTimestamps := req.GetView() == adminv1.View_VIEW_STANDARD || req.GetView() == adminv1.View_VIEW_FULL
	result.Groups = make([]*adminv1.Group, 0, len(groupList))
	for _, g := range groupList {
		item, mapErr := groupToProto(g, includeTimestamps)
		if mapErr != nil {
			return nil, errs.FailedPrecondition(ctx).WithMessage(mapErr.Error())
		}
		result.Groups = append(result.Groups, item)
	}
	if cursorMode && len(groupList) == int(pageSize) && len(groupList) > 0 {
		result.NextPageToken = encodeGroupIDPageToken(groupList[len(groupList)-1].ID)
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
		groups.FieldSourceID,
		groups.FieldConfig,
		groups.FieldVisibility,
		groups.FieldProtected,
		groups.FieldDescription,
		groups.FieldCreatedBy,
		groups.FieldUpdatedBy,
		groups.FieldCreatedAt,
		groups.FieldUpdatedAt,
		groups.FieldDeletedAt,
	).Where(groups.ID(int(req.Id))).Only(ctx)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("group not found")
	}

	// 详情接口默认返回完整信息（含时间戳）
	result, err := groupToProto(group, true)
	if err != nil {
		return nil, errs.FailedPrecondition(ctx).WithMessage(err.Error())
	}
	return result, nil
}

// parseListGroupsFilter 解析 filter 字符串为 predicate 列表，支持 key=value 与 AND 组合
func parseListGroupsFilter(filter string) ([]predicate.Groups, bool, error) {
	out := make([]predicate.Groups, 0)
	deletedOnly := false
	parts := strings.Split(filter, " AND ")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, false, fmt.Errorf("empty filter clause")
		}
		if strings.EqualFold(strings.ReplaceAll(p, " ", ""), "deleted_at!=null") {
			deletedOnly = true
			continue
		}
		idx := strings.Index(p, "=")
		if idx <= 0 {
			return nil, false, fmt.Errorf("unsupported filter clause %q", p)
		}
		if idx > 0 && p[idx-1] == '!' {
			return nil, false, fmt.Errorf("unsupported filter clause %q", p)
		}
		key := strings.TrimSpace(strings.Trim(p[:idx], "\""))
		val := strings.TrimSpace(strings.Trim(p[idx+1:], "\""))
		switch key {
		case "status", "group_status":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, false, fmt.Errorf("status must be int: %s", val)
			}
			out = append(out, groups.GroupStatus(n))
		case "type", "group_type":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, false, fmt.Errorf("type must be int: %s", val)
			}
			out = append(out, groups.GroupType(n))
		case "parent_id":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, false, fmt.Errorf("parent_id must be int: %s", val)
			}
			out = append(out, groups.ParentID(n))
		case "code":
			out = append(out, groups.CodeContainsFold(val))
		case "display_name":
			out = append(out, groups.DisplayNameContainsFold(val))
		default:
			return nil, false, fmt.Errorf("unsupported filter field %q", key)
		}
	}
	return out, deletedOnly, nil
}

func groupToProto(g *lion.Groups, includeTimestamps bool) (*adminv1.Group, error) {
	grp := &adminv1.Group{
		Id:          int64(g.ID),
		Code:        g.Code,
		Type:        adminv1.Group_Type(g.GroupType),
		Status:      adminv1.Group_Status(g.GroupStatus),
		DisplayName: g.DisplayName,
		SortOrder:   int32(g.SortOrder),
		MaxMembers:  int32(g.MaxMembers),
		Metadata:    g.Metadata,
		ParentId:    int64(g.ParentID),
		Visibility:  adminv1.Visibility(g.Visibility),
		Protected:   g.Protected,
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
	// 读取路径对外只暴露组 ID 与错误类别，不透传存量配置细节（§4.1/§4.1.4）。
	if err := populateGroupProtoConfig(grp, g); err != nil {
		return nil, fmt.Errorf("group %d has invalid type config", g.ID)
	}
	return grp, nil
}

func sortGroupSlice(s []*adminv1.Group) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].SortOrder != s[j].SortOrder {
			return s[i].SortOrder < s[j].SortOrder
		}
		return s[i].Id < s[j].Id
	})
}

// UpdateGroup 更新用户组；code、type 以及来源绑定创建后不可修改。
func (a *KnownAdminAPI) UpdateGroup(ctx context.Context, req *adminv1.UpdateGroupRequest) (*adminv1.Group, error) {
	if req.Group == nil || req.Group.Id <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("group and group.id are required")
	}
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	row, err := tx.Groups.Query().Where(groups.IDEQ(int(req.Group.Id)), groups.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		return nil, err
	}
	// Capacity mutations use a single lock order (setting row, then group row),
	// matching initialization and avoiding a seed/update deadlock.
	if row.GroupType == int(adminv1.Group_DYNAMIC) || row.GroupType == int(adminv1.Group_SYSTEM) {
		if err := lockActiveRuleGroupCapacity(ctx, tx); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Groups.Update().Where(groups.IDEQ(row.ID), groups.DeletedAtIsNil()).SetUpdatedAt(row.UpdatedAt).Save(ctx); err != nil {
		return nil, err
	}
	// The first query supplies the no-op update value; re-read after acquiring
	// the row lock so concurrent updates cannot leave this request validating
	// stale status/config/max_members values.
	row, err = tx.Groups.Query().Where(groups.IDEQ(row.ID), groups.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		return nil, err
	}
	current, err := groupToProto(row, false)
	if err != nil {
		return nil, errs.FailedPrecondition(ctx).WithMessage(err.Error())
	}
	isSystem := current.Type == adminv1.Group_SYSTEM
	update := tx.Groups.Update().Where(groups.IDEQ(row.ID), groups.DeletedAtIsNil())
	updatedBy := req.Group.UpdatedBy
	if updatedBy == 0 {
		if uid, userErr := GetUserID(ctx); userErr == nil {
			updatedBy = uid
		}
	}
	paths := []string(nil)
	if req.UpdateMask != nil {
		paths = req.UpdateMask.Paths
	}
	if len(paths) == 0 {
		paths = []string{"display_name", "status", "sort_order", "max_members", "metadata", "description", "visibility"}
		if current.Type == adminv1.Group_DYNAMIC && req.Group.GetDynamicConfig() != nil {
			paths = append(paths, "dynamic_config.user_filter")
		}
	}
	for _, path := range paths {
		switch path {
		case "code":
			if err := validateImmutableString(ctx, "group", "code", row.Code, req.Group.Code); err != nil {
				return nil, err
			}
		case "type":
			if req.Group.Type != current.Type {
				return nil, immutableFieldError(ctx, "group", "type")
			}
		case "parent_id":
			if req.Group.ParentId != 0 {
				return nil, errs.InvalidArgument(ctx).WithMessage("parent_id must be 0 until group hierarchy is enabled")
			}
		case "department_config", "department_config.department_id", "role_config", "role_config.role_id":
			return nil, immutableFieldError(ctx, "group", path)
		case "system_config", "system_config.user_filter":
			return nil, errs.FailedPrecondition(ctx).WithMessage("SYSTEM group config is managed by system seed")
		case "dynamic_config", "dynamic_config.user_filter":
			if isSystem || current.Type != adminv1.Group_DYNAMIC || req.Group.GetDynamicConfig() == nil {
				return nil, errs.InvalidArgument(ctx).WithMessage("dynamic_config is only valid for DYNAMIC groups")
			}
			current.Config = req.Group.Config
		case "protected":
			return nil, errs.InvalidArgument(ctx).WithMessage("protected field is managed by system")
		case "display_name":
			current.DisplayName = req.Group.DisplayName
			update.SetDisplayName(req.Group.DisplayName)
		case "status":
			current.Status = req.Group.Status
			update.SetGroupStatus(int(req.Group.Status))
		case "sort_order":
			update.SetSortOrder(int(req.Group.SortOrder))
		case "max_members":
			current.MaxMembers = req.Group.MaxMembers
			update.SetMaxMembers(int(req.Group.MaxMembers))
		case "metadata":
			update.SetMetadata(req.Group.Metadata)
		case "description":
			update.SetDescription(req.Group.Description)
		case "visibility":
			update.SetVisibility(int(req.Group.Visibility))
		case "updated_by":
		default:
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("unsupported update field %q", path))
		}
	}
	validated, err := validateGroupTypeConfig(ctx, tx.Client(), current, isSystem)
	if err != nil {
		return nil, groupConfigWriteError(ctx, err)
	}
	if current.MaxMembers > 0 {
		count, countErr := tx.UserMemberships.Query().Where(
			usermemberships.TargetTypeEQ(membershipTargetGroup),
			usermemberships.TargetIDEQ(row.ID),
		).Count(ctx)
		if countErr != nil {
			return nil, countErr
		}
		if count > int(current.MaxMembers) {
			return nil, errs.FailedPrecondition(ctx).WithMessage("max_members is lower than existing direct membership count")
		}
	}
	if (current.Type == adminv1.Group_DYNAMIC || current.Type == adminv1.Group_SYSTEM) &&
		row.GroupStatus != int(adminv1.Group_ACTIVE) && current.Status == adminv1.Group_ACTIVE {
		if err := checkActiveRuleGroupCapacity(ctx, tx, 1); err != nil {
			return nil, err
		}
	}
	if current.Type == adminv1.Group_DYNAMIC {
		update.SetConfig(validated.config)
	}
	update.SetUpdatedBy(updatedBy)
	affected, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}
	if affected != 1 {
		return nil, errs.NotFound(ctx).WithMessage("group not found")
	}
	updated, err := tx.Groups.Query().Where(groups.IDEQ(row.ID), groups.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		return nil, err
	}
	result, err := groupToProto(updated, true)
	if err != nil {
		return nil, errs.FailedPrecondition(ctx).WithMessage(err.Error())
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// ListGroupMembers 获取群组成员列表
// 根据群组类型从不同数据源获取成员：
//   - DEPARTMENT: 从 user_departments 表查询关联部门的成员
//   - ROLE: 从 user_roles 表查询关联角色的成员
//   - DYNAMIC: 根据 dynamic_config.user_filter 从 users 表查询
//   - SYSTEM: 同 DYNAMIC，根据 system_config.user_filter 查询（系统内置，不可创建/修改/删除）
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
	group, err := db.Groups.Query().Where(groups.IDEQ(groupID), groups.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		return result, err
	}

	groupType := adminv1.Group_Type(group.GroupType)
	if _, err := groupToProto(group, false); err != nil {
		return nil, errs.FailedPrecondition(ctx).WithMessage(err.Error())
	}

	// 根据群组类型路由到不同的数据源
	switch groupType {
	case adminv1.Group_DEPARTMENT:
		if err := requireActiveDepartmentGroupReference(ctx, db, *group.SourceID); err != nil {
			return result, errs.FailedPrecondition(ctx).WithMessage(err.Error())
		}
		return a.listGroupMembersFromDepartment(ctx, req, db, *group.SourceID)
	case adminv1.Group_ROLE:
		return a.listGroupMembersFromRole(ctx, req, db, groupID, *group.SourceID)
	case adminv1.Group_DYNAMIC, adminv1.Group_SYSTEM:
		compiled, configErr := decodeStoredUserFilter(group.Config)
		if configErr != nil {
			return nil, errs.FailedPrecondition(ctx).WithMessage("group config is invalid")
		}
		return a.listGroupMembersFromDynamicRule(ctx, req, db, compiled)
	default:
		return a.listGroupMembersFromGroupMembers(ctx, req, db, groupID)
	}
}

// listGroupMembersFromDepartment 从 department_members 表查询部门群组成员
func (a *KnownAdminAPI) listGroupMembersFromDepartment(ctx context.Context, req *adminv1.ListGroupMembersRequest, db *lion.Client, departmentID int) (*adminv1.ListGroupMembersResponse, error) {
	result := &adminv1.ListGroupMembersResponse{
		Members: make([]*adminv1.Membership, 0),
	}

	if departmentID == 0 {
		return result, nil
	}

	memberQuery := db.UserMemberships.Query().Where(
		usermemberships.TargetTypeEQ(membershipTargetDepartment),
		usermemberships.TargetIDEQ(departmentID),
		usermemberships.MemberStatusEQ(int(adminv1.Membership_ACTIVE)),
		usermemberships.Or(usermemberships.ExpiresAtIsNil(), usermemberships.ExpiresAtGT(time.Now())),
		usermemberships.HasLionUsersWith(users.DeletedAtIsNil()),
	)

	_, cursorMode := req.GetPagination().(*adminv1.ListGroupMembersRequest_PageToken)
	if cursorMode {
		if err := requireIDCursorOrder(ctx, req.GetOrderBy()); err != nil {
			return nil, err
		}
		memberQuery = memberQuery.Order(lion.Desc(usermemberships.FieldID))
	} else {
		switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
		case "created_at desc", "create_time desc":
			memberQuery = memberQuery.Order(lion.Desc(usermemberships.FieldCreatedAt), lion.Desc(usermemberships.FieldID))
		case "created_at asc", "create_time asc":
			memberQuery = memberQuery.Order(lion.Asc(usermemberships.FieldCreatedAt), lion.Asc(usermemberships.FieldID))
		default:
			memberQuery = memberQuery.Order(lion.Desc(usermemberships.FieldID))
		}
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
		lastID, tokenErr := decodeGroupIDPageToken(ctx, p.PageToken)
		if tokenErr != nil {
			return nil, tokenErr
		}
		if lastID > 0 {
			memberQuery = memberQuery.Where(usermemberships.IDLT(lastID))
		}
	}
	memberQuery = memberQuery.Limit(int(pageSize))

	members, err := memberQuery.Select(
		usermemberships.FieldID,
		usermemberships.FieldUserID,
		usermemberships.FieldTargetType,
		usermemberships.FieldTargetID,
		usermemberships.FieldMemberRole,
		usermemberships.FieldMemberStatus,
		usermemberships.FieldMemberType,
		usermemberships.FieldJoinedAt,
		usermemberships.FieldExpiresAt,
		usermemberships.FieldDescription,
		usermemberships.FieldMetadata,
		usermemberships.FieldCreatedBy,
		usermemberships.FieldUpdatedBy,
		usermemberships.FieldCreatedAt,
		usermemberships.FieldUpdatedAt,
	).WithLionUsers(func(q *lion.UsersQuery) {
		q.Select(users.FieldID, users.FieldUsername, users.FieldNickname).Where(users.DeletedAtIsNil())
	}).All(ctx)
	if err != nil {
		return nil, err
	}

	for _, member := range members {
		result.Members = append(result.Members, userMembershipToProto(member))
	}

	// Cursor 分页
	if cursorMode && len(members) == int(pageSize) && len(members) > 0 {
		result.NextPageToken = encodeGroupIDPageToken(members[len(members)-1].ID)
	}

	return result, nil
}

// listGroupMembersFromRole paginates the final, deduplicated user set. Paging
// principal-role bindings first is incorrect because one binding may expand to
// many users and the same user may be reached through several principals.
func (a *KnownAdminAPI) listGroupMembersFromRole(ctx context.Context, req *adminv1.ListGroupMembersRequest, db *lion.Client, groupID, roleID int) (*adminv1.ListGroupMembersResponse, error) {
	result := &adminv1.ListGroupMembersResponse{Members: make([]*adminv1.Membership, 0)}
	exists, err := db.Roles.Query().Where(
		roles.IDEQ(roleID),
		roles.RoleStatusEQ(int(adminv1.Role_ACTIVE)),
		roles.DeletedAtIsNil(),
	).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errs.FailedPrecondition(ctx).WithMessage("role group reference must be active and not deleted")
	}
	if err := a.checkRolePermission(ctx, db, roleID); err != nil {
		return nil, err
	}

	where, err := roleGroupUserPredicates(ctx, db, roleID, time.Now())
	if err != nil {
		return nil, err
	}
	query := db.Users.Query().Where(where...)
	_, cursorMode := req.GetPagination().(*adminv1.ListGroupMembersRequest_PageToken)
	if cursorMode {
		if err := requireIDCursorOrder(ctx, req.GetOrderBy()); err != nil {
			return nil, err
		}
		query = query.Order(lion.Asc(users.FieldID))
	} else {
		switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
		case "created_at desc", "create_time desc":
			query = query.Order(lion.Desc(users.FieldCreatedAt), lion.Desc(users.FieldID))
		case "created_at asc", "create_time asc":
			query = query.Order(lion.Asc(users.FieldCreatedAt), lion.Asc(users.FieldID))
		default:
			query = query.Order(lion.Asc(users.FieldID))
		}
	}

	totalSize, err := query.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)
	pageSize := GetPageSize(ctx, req.GetPageSize())
	switch p := req.GetPagination().(type) {
	case *adminv1.ListGroupMembersRequest_Offset:
		query = query.Offset(int(p.Offset))
	case *adminv1.ListGroupMembersRequest_PageToken:
		lastID, tokenErr := decodeGroupIDPageToken(ctx, p.PageToken)
		if tokenErr != nil {
			return nil, tokenErr
		}
		if lastID > 0 {
			query = query.Where(users.IDGT(lastID))
		}
	}
	userList, err := query.Select(users.FieldID, users.FieldUsername, users.FieldNickname).
		Limit(int(pageSize)).
		All(ctx)
	if err != nil {
		return nil, err
	}
	for _, user := range userList {
		result.Members = append(result.Members, &adminv1.Membership{
			UserId:       int64(user.ID),
			Username:     user.Username,
			Nickname:     user.Nickname,
			TargetType:   adminv1.Membership_GROUP,
			TargetId:     int64(groupID),
			MemberStatus: adminv1.Membership_ACTIVE,
		})
	}
	if cursorMode && len(userList) == int(pageSize) && len(userList) > 0 {
		result.NextPageToken = encodeGroupIDPageToken(userList[len(userList)-1].ID)
	}
	return result, nil
}

// dynamicRuleAllowedFields 动态规则允许过滤的用户字段白名单（非敏感、非加密字段）
// listGroupMembersFromDynamicRule 根据动态规则表达式从 users 表查询成员
func (a *KnownAdminAPI) listGroupMembersFromDynamicRule(ctx context.Context, req *adminv1.ListGroupMembersRequest, db *lion.Client, rule *compiledUserFilter) (*adminv1.ListGroupMembersResponse, error) {
	result := &adminv1.ListGroupMembersResponse{
		Members: make([]*adminv1.Membership, 0),
	}

	query := db.Users.Query().Where(users.DeletedAtIsNil()).Where(rule.predicates()...)
	_, cursorMode := req.GetPagination().(*adminv1.ListGroupMembersRequest_PageToken)
	if cursorMode {
		if err := requireIDCursorOrder(ctx, req.GetOrderBy()); err != nil {
			return nil, err
		}
		query = query.Order(lion.Asc(users.FieldID))
	} else {
		switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
		case "created_at desc", "create_time desc":
			query = query.Order(lion.Desc(users.FieldCreatedAt), lion.Desc(users.FieldID))
		case "created_at asc", "create_time asc":
			query = query.Order(lion.Asc(users.FieldCreatedAt), lion.Asc(users.FieldID))
		default:
			query = query.Order(lion.Asc(users.FieldID))
		}
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
		lastID, tokenErr := decodeGroupIDPageToken(ctx, p.PageToken)
		if tokenErr != nil {
			return nil, tokenErr
		}
		if lastID > 0 {
			query = query.Where(users.IDGT(lastID))
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
		})
	}

	// Cursor 分页
	if cursorMode && len(userList) == int(pageSize) && len(userList) > 0 {
		result.NextPageToken = encodeGroupIDPageToken(userList[len(userList)-1].ID)
	}

	return result, nil
}

// listGroupMembersFromGroupMembers 从 group_members 表查询普通群组成员（默认方式）
func (a *KnownAdminAPI) listGroupMembersFromGroupMembers(ctx context.Context, req *adminv1.ListGroupMembersRequest, db *lion.Client, groupID int) (*adminv1.ListGroupMembersResponse, error) {
	result := &adminv1.ListGroupMembersResponse{
		Members: make([]*adminv1.Membership, 0),
	}

	where := []predicate.UserMemberships{
		usermemberships.TargetTypeEQ(membershipTargetGroup),
		usermemberships.TargetIDEQ(groupID),
	}
	if req.GetFilter() != "" {
		filterPredicates, err := parseListGroupMembersFilter(req.GetFilter())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid filter: %v", err))
		}
		where = append(where, filterPredicates...)
	}

	query := db.UserMemberships.Query().Where(where...)

	_, cursorMode := req.GetPagination().(*adminv1.ListGroupMembersRequest_PageToken)
	if cursorMode {
		if err := requireIDCursorOrder(ctx, req.GetOrderBy()); err != nil {
			return nil, err
		}
		query = query.Order(lion.Desc(usermemberships.FieldID))
	} else if req.GetOrderBy() != "" {
		switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
		case "joined_at desc":
			query = query.Order(lion.Desc(usermemberships.FieldJoinedAt), lion.Desc(usermemberships.FieldID))
		case "joined_at asc":
			query = query.Order(lion.Asc(usermemberships.FieldJoinedAt), lion.Asc(usermemberships.FieldID))
		case "create_time desc", "created_at desc":
			query = query.Order(lion.Desc(usermemberships.FieldCreatedAt), lion.Desc(usermemberships.FieldID))
		case "create_time asc", "created_at asc":
			query = query.Order(lion.Asc(usermemberships.FieldCreatedAt), lion.Asc(usermemberships.FieldID))
		default:
			query = query.Order(lion.Desc(usermemberships.FieldCreatedAt), lion.Desc(usermemberships.FieldID))
		}
	} else {
		query = query.Order(lion.Desc(usermemberships.FieldCreatedAt), lion.Desc(usermemberships.FieldID))
	}

	totalSize, err := query.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	pageSize := GetPageSize(ctx, req.GetPageSize())
	switch p := req.GetPagination().(type) {
	case *adminv1.ListGroupMembersRequest_Offset:
		query = query.Offset(int(p.Offset))
	case *adminv1.ListGroupMembersRequest_PageToken:
		lastID, tokenErr := decodeGroupIDPageToken(ctx, p.PageToken)
		if tokenErr != nil {
			return nil, tokenErr
		}
		if lastID > 0 {
			query = query.Where(usermemberships.IDLT(lastID))
		}
	}
	query = query.Limit(int(pageSize))

	members, err := query.Select(
		usermemberships.FieldID,
		usermemberships.FieldUserID,
		usermemberships.FieldTargetType,
		usermemberships.FieldTargetID,
		usermemberships.FieldMemberRole,
		usermemberships.FieldMemberStatus,
		usermemberships.FieldJoinedAt,
		usermemberships.FieldExpiresAt,
		usermemberships.FieldMetadata,
		usermemberships.FieldDescription,
		usermemberships.FieldCreatedBy,
		usermemberships.FieldUpdatedBy,
		usermemberships.FieldCreatedAt,
		usermemberships.FieldUpdatedAt,
	).WithLionUsers(func(q *lion.UsersQuery) {
		q.Select(users.FieldID, users.FieldUsername, users.FieldNickname)
	}).All(ctx)
	if err != nil {
		return nil, err
	}

	for _, member := range members {
		result.Members = append(result.Members, userMembershipToProto(member))
	}

	if cursorMode && len(members) == int(pageSize) && len(members) > 0 {
		result.NextPageToken = encodeGroupIDPageToken(members[len(members)-1].ID)
	}

	return result, nil
}

// parseListGroupMembersFilter 解析 filter，支持 member_status=2, member_role=3
func parseListGroupMembersFilter(filter string) ([]predicate.UserMemberships, error) {
	var out []predicate.UserMemberships
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
			out = append(out, usermemberships.MemberStatusEQ(n))
		case "member_role", "role":
			n, err := strconv.Atoi(val)
			if err != nil {
				return nil, fmt.Errorf("member_role must be int: %s", val)
			}
			out = append(out, usermemberships.MemberRoleEQ(n))
		}
	}
	return out, nil
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
	seen := make(map[int64]struct{}, len(req.Members))
	for _, member := range req.Members {
		if member == nil || member.UserId <= 0 {
			return result, errs.InvalidArgument(ctx).WithMessage("each member.user_id must be positive")
		}
		if _, duplicate := seen[member.UserId]; duplicate {
			return result, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("duplicate member user_id %d", member.UserId))
		}
		seen[member.UserId] = struct{}{}
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	group, err := tx.Groups.Query().Where(groups.IDEQ(groupID), groups.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		return result, err
	}
	if _, err := tx.Groups.Update().Where(groups.IDEQ(groupID), groups.DeletedAtIsNil()).SetUpdatedAt(group.UpdatedAt).Save(ctx); err != nil {
		return result, err
	}
	group, err = tx.Groups.Query().Where(groups.IDEQ(groupID), groups.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		return result, err
	}
	groupType := adminv1.Group_Type(group.GroupType)
	if _, err := groupToProto(group, false); err != nil {
		return result, errs.FailedPrecondition(ctx).WithMessage(err.Error())
	}
	if isAutoManagedGroupType(groupType) {
		return result, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("%s type groups do not support manual member management", groupType))
	}
	memberIDs := make([]int, 0, len(req.Members))
	for _, member := range req.Members {
		memberIDs = append(memberIDs, int(member.UserId))
	}
	if len(memberIDs) > 0 {
		existing, queryErr := tx.UserMemberships.Query().Where(
			usermemberships.TargetTypeEQ(membershipTargetGroup),
			usermemberships.TargetIDEQ(groupID),
			usermemberships.UserIDIn(memberIDs...),
		).Exist(ctx)
		if queryErr != nil {
			return result, queryErr
		}
		if existing {
			return result, errs.AlreadyExists(ctx).WithMessage("one or more users are already group members")
		}
	}
	existingCount, err := tx.UserMemberships.Query().Where(
		usermemberships.TargetTypeEQ(membershipTargetGroup),
		usermemberships.TargetIDEQ(groupID),
	).Count(ctx)
	if err != nil {
		return result, err
	}
	if group.MaxMembers > 0 && existingCount+len(req.Members) > group.MaxMembers {
		return result, errs.ResourceExhausted(ctx).WithMessage("group max_members limit exceeded")
	}
	allMembers := make([]*lion.UserMembershipsCreate, 0, len(req.Members))
	for _, member := range req.Members {
		create := tx.UserMemberships.Create().
			SetUserID(int(member.UserId)).
			SetTargetType(membershipTargetGroup).
			SetTargetID(groupID).
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

		if member.ExpiresAt != nil && !member.ExpiresAt.AsTime().IsZero() {
			create = create.SetExpiresAt(member.ExpiresAt.AsTime())
		}
		if len(member.Metadata) > 0 {
			create = create.SetMetadata(member.Metadata)
		}

		allMembers = append(allMembers, create)
	}

	if len(allMembers) > 0 {
		if _, err = tx.UserMemberships.CreateBulk(allMembers...).Save(ctx); err != nil {
			return result, err
		}
	}
	if err := tx.Commit(); err != nil {
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

	_, err = db.UserMemberships.Delete().
		Where(
			usermemberships.TargetTypeEQ(membershipTargetGroup),
			usermemberships.TargetIDEQ(groupID),
			usermemberships.UserIDEQ(int(req.UserId)),
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

	member, err := db.UserMemberships.Query().
		Where(
			usermemberships.TargetTypeEQ(membershipTargetGroup),
			usermemberships.TargetIDEQ(groupID),
			usermemberships.UserIDEQ(int(req.UserId)),
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
			case "expires_at":
				if req.Member.ExpiresAt != nil {
					update.SetExpiresAt(req.Member.ExpiresAt.AsTime())
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
		if req.Member.ExpiresAt != nil {
			update.SetExpiresAt(req.Member.ExpiresAt.AsTime())
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
	updated, err = db.UserMemberships.Query().
		Where(usermemberships.IDEQ(updated.ID)).
		WithLionUsers(func(q *lion.UsersQuery) {
			q.Select(users.FieldID, users.FieldUsername, users.FieldNickname)
		}).
		Only(ctx)
	if err != nil {
		return userMembershipToProto(updated), nil
	}

	return userMembershipToProto(updated), nil
}
