package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/grpc-kit/pkg/lion/schema"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/predicate"

	// 数据范围表已注释，同步取消依赖
	// "github.com/grpc-kit/pkg/lion/roledataranges"
	// "github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/departmentmembers"
)

// CreateDepartment 创建部门
// 请求字段与 proto Department 定义对齐，支持：parent_id, code, display_name, type, status, sort_order,
// description, cost_center_code, budget_item_code, max_members, external_id, metadata；created_by/updated_by 从上下文获取
func (a *KnownAdminAPI) CreateDepartment(ctx context.Context, req *adminv1.CreateDepartmentRequest) (*adminv1.Department, error) {
	result := &adminv1.Department{}

	if req == nil || req.Department == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body department is nil")
	}

	code, err := schema.EnsureCode(req.Department.Code)
	if err != nil {
		return result, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	req.Department.Code = code

	tx, err := a.config.db.Tx(ctx)
	if err != nil {
		return result, err
	}

	// 确认父部门存在并检查权限
	if req.Department.ParentId != 0 {
		_, err = tx.Departments.Get(ctx, int(req.Department.ParentId))
		if err != nil {
			_ = tx.Rollback()
			return result, errs.InvalidArgument(ctx).WithMessage("department parent id not found")
		}

		// 检查用户是否有权限操作父部门（创建子部门需要父部门权限）
		if err := a.checkDepartmentPermissionTx(ctx, tx, int(req.Department.ParentId)); err != nil {
			_ = tx.Rollback()
			return result, err
		}
	} else {
		// 创建根部门（parent_id = 0）需要检查用户是否有权限操作根部门
		if err := a.checkDepartmentPermissionTx(ctx, tx, 0); err != nil {
			_ = tx.Rollback()
			return result, err
		}
	}

	// display_name：请求未提供时使用 code
	displayName := req.Department.DisplayName
	if displayName == "" {
		displayName = req.Department.Code
	}

	// sort_order：未指定时使用默认 100
	sortOrder := int(req.Department.SortOrder)
	if sortOrder == 0 {
		sortOrder = 100
	}

	// 可见性：未指定时默认 SUBTREE（本部门及下属可见）
	visibility := int(req.Department.Visibility)
	if req.Department.Visibility == adminv1.Visibility_VISIBILITY_UNSPECIFIED {
		visibility = int(adminv1.Visibility_VISIBILITY_SUBTREE.Number())
	}

	create := tx.Departments.Create().
		SetParentID(int(req.Department.ParentId)).
		SetCode(req.Department.Code).
		SetDisplayName(displayName).
		SetSortOrder(sortOrder).
		SetDepartmentType(int(req.Department.Type)).
		SetDepartmentStatus(int(req.Department.Status)).
		SetVisibility(visibility)

	if req.Department.Description != "" {
		create = create.SetDescription(req.Department.Description)
	}
	if req.Department.CostCenterCode != "" {
		create = create.SetCostCenterCode(req.Department.CostCenterCode)
	}
	if req.Department.BudgetItemCode != "" {
		create = create.SetBudgetItemCode(req.Department.BudgetItemCode)
	}
	if req.Department.MaxMembers != 0 {
		create = create.SetMaxMembers(int(req.Department.MaxMembers))
	}
	if req.Department.ExternalId != "" {
		create = create.SetExternalID(req.Department.ExternalId)
	}
	if len(req.Department.Metadata) > 0 {
		create = create.SetMetadata(req.Department.Metadata)
	}

	// 从上下文设置创建人/更新人（审计）
	if userID, err := GetUserID(ctx); err == nil {
		create = create.SetCreatedBy(userID).SetUpdatedBy(userID)
	}

	dp, err := create.Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return result, err
	}

	// 返回与 proto Department 一致的完整信息（不含 managers，创建时无成员）
	result = &adminv1.Department{
		Id:             int64(dp.ID),
		ParentId:       int64(dp.ParentID),
		Code:           dp.Code,
		DisplayName:    dp.DisplayName,
		Type:           adminv1.Department_Type(dp.DepartmentType),
		Status:         adminv1.Department_Status(dp.DepartmentStatus),
		SortOrder:      int32(dp.SortOrder),
		Visibility:     adminv1.Visibility(dp.Visibility),
		Description:    dp.Description,
		CostCenterCode: dp.CostCenterCode,
		BudgetItemCode: dp.BudgetItemCode,
		MaxMembers:     int32(dp.MaxMembers),
		ExternalId:     dp.ExternalID,
		Metadata:       dp.Metadata,
		CreatedBy:      dp.CreatedBy,
		UpdatedBy:      dp.UpdatedBy,
		CreatedAt:      timestamppb.New(dp.CreatedAt),
		UpdatedAt:      timestamppb.New(dp.UpdatedAt),
		Members:        make([]*adminv1.Membership, 0),
	}

	_ = tx.Commit()

	return result, nil
}

// parseListDepartmentsParent 解析 ListDepartments 的 parent 参数。
// 格式: "departments/123" 表示 parent_id=123；"departments" 或 "departments/0" 表示仅根部门；空表示不按父级过滤。
// 返回: parentID, filterByParent（是否按 parent 过滤）。
func parseListDepartmentsParent(parent string) (parentID int, filterByParent bool) {
	if parent == "" {
		return 0, false
	}
	prefix := "departments/"
	if strings.HasPrefix(parent, prefix) {
		idStr := strings.TrimPrefix(parent, prefix)
		if idStr == "" || idStr == "0" {
			return 0, true
		}
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return 0, false
		}
		return id, true
	}
	// 兼容仅传部门 ID 的情况
	id, err := strconv.Atoi(parent)
	if err != nil {
		return 0, false
	}
	return id, true
}

// ListDepartments 列出部门
func (a *KnownAdminAPI) ListDepartments(ctx context.Context, req *adminv1.ListDepartmentsRequest) (*adminv1.ListDepartmentsResponse, error) {
	result := &adminv1.ListDepartmentsResponse{}

	rids, err := a.getUserRoleID(ctx)
	if err != nil {
		return result, err
	}

	if len(rids) == 0 {
		result.Departments = []*adminv1.Department{}
		return result, nil
	}

	allDeps, err := a.config.db.Departments.Query().Select(departments.FieldID).All(ctx)
	if err != nil {
		return result, err
	}
	candidateIDs := make([]int, 0, len(allDeps))
	for _, d := range allDeps {
		candidateIDs = append(candidateIDs, d.ID)
	}
	if len(candidateIDs) == 0 {
		result.Departments = []*adminv1.Department{}
		return result, nil
	}

	// 按可见性策略过滤：GLOBAL/SUBTREE/LOCAL/RESTRICTED/SPECIFIC
	depIDList, err := a.getVisibleDepartmentIDs(ctx, a.config.db, candidateIDs)
	if err != nil {
		return result, err
	}
	if len(depIDList) == 0 {
		result.Departments = []*adminv1.Department{}
		return result, nil
	}

	// 构建查询条件
	where := []predicate.Departments{departments.IDIn(depIDList...)}

	parentID, filterByParent := parseListDepartmentsParent(req.GetParent())
	if filterByParent {
		where = append(where, departments.ParentIDEQ(parentID))
	}
	if req.DepartmentType != 0 {
		where = append(where, departments.DepartmentTypeEQ(int(req.DepartmentType)))
	}
	if req.DepartmentStatus != 0 {
		where = append(where, departments.DepartmentStatusEQ(int(req.DepartmentStatus)))
	}

	depQuery := a.config.db.Departments.Query().Where(where...)

	// 排序
	if req.OrderBy != "" {
		switch req.OrderBy {
		case "sort_order asc":
			depQuery = depQuery.Order(lion.Asc(departments.FieldSortOrder))
		case "sort_order desc":
			depQuery = depQuery.Order(lion.Desc(departments.FieldSortOrder))
		case "create_time desc":
			depQuery = depQuery.Order(lion.Desc(departments.FieldCreatedAt))
		case "create_time asc":
			depQuery = depQuery.Order(lion.Asc(departments.FieldCreatedAt))
		default:
			depQuery = depQuery.Order(lion.Asc(departments.FieldSortOrder), lion.Asc(departments.FieldID))
		}
	} else {
		depQuery = depQuery.Order(lion.Asc(departments.FieldSortOrder), lion.Asc(departments.FieldID))
	}

	// 在分页前计算总数
	totalSize, err := depQuery.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	pageSize := GetPageSizeByStructure(ctx, req.PageSize, req.Structure)

	// Cursor-based 分页
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
			depQuery = depQuery.Where(departments.IDGT(lastID))
		}
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListDepartmentsRequest_Offset:
		depQuery = depQuery.Offset(int(p.Offset))
	case *adminv1.ListDepartmentsRequest_PageToken:
		// cursor 已在上面处理
	}

	depQuery = depQuery.Limit(int(pageSize))

	// View FULL 时预加载部门成员列表（含用户信息）
	if req.View == adminv1.View_VIEW_FULL {
		depQuery = depQuery.WithLionDepartmentMembers(
			func(query *lion.DepartmentMembersQuery) {
				query.WithLionUsers()
			},
		)
	}

	depObj, err := depQuery.All(ctx)
	if err != nil {
		return nil, err
	}

	// 将 ent 实体转为 proto，并按 structure 返回平铺或树形
	depToProto := func(m *lion.Departments) *adminv1.Department {
		menu := &adminv1.Department{
			Id:          int64(m.ID),
			ParentId:    int64(m.ParentID),
			Code:        m.Code,
			DisplayName: I18NName(m.Code),
			SortOrder:   int32(m.SortOrder),
			Type:        adminv1.Department_Type(m.DepartmentType),
			Status:      adminv1.Department_Status(m.DepartmentStatus),
			Visibility:  adminv1.Visibility(m.Visibility),
			Members:     make([]*adminv1.Membership, 0),
		}
		if req.View == adminv1.View_VIEW_FULL && m.Edges.LionDepartmentMembers != nil {
			for _, l := range m.Edges.LionDepartmentMembers {
				pm := &adminv1.Membership{
					Id:           int64(l.ID),
					UserId:       int64(l.UserID),
					TargetType:   adminv1.Membership_DEPARTMENT,
					TargetId:     int64(l.DepartmentID),
					MemberRole:   adminv1.Membership_Role(l.MemberRole),
					MemberStatus: adminv1.Membership_Status(l.MemberStatus),
					MemberType:   adminv1.Membership_MemberType(l.MemberType),
					Description:  l.Description,
					CreatedBy:    l.CreatedBy,
					UpdatedBy:    l.UpdatedBy,
					CreatedAt:    timestamppb.New(l.CreatedAt),
					UpdatedAt:    timestamppb.New(l.UpdatedAt),
				}
				if l.Edges.LionUsers != nil {
					pm.Username = l.Edges.LionUsers.Username
					pm.Nickname = l.Edges.LionUsers.Nickname
				}
				if l.Metadata != "" {
					pm.Metadata = MetadataParse(l.Metadata)
				}
				menu.Members = append(menu.Members, pm)
			}
		}
		return menu
	}

	if req.Structure == adminv1.Structure_STRUCTURE_TREE || req.Structure == adminv1.Structure_STRUCTURE_TREE_EXPANDED {
		// 树形：用当前页数据构建树（仅包含本页节点及其在本页内的父子关系）
		menuMap := make(map[int64]*adminv1.Department)
		var roots []*adminv1.Department

		for _, m := range depObj {
			menu := depToProto(m)
			menuMap[int64(m.ID)] = menu
		}
		for _, menu := range menuMap {
			if menu.ParentId == 0 {
				roots = append(roots, menu)
				continue
			}
			if parent, ok := menuMap[menu.ParentId]; ok {
				parent.Children = append(parent.Children, menu)
			} else {
				roots = append(roots, menu)
			}
		}
		sort.Slice(roots, func(i, j int) bool {
			return roots[i].SortOrder < roots[j].SortOrder
		})
		result.Departments = roots
	} else {
		// 平铺列表（FLAT 或未指定）
		for _, m := range depObj {
			result.Departments = append(result.Departments, depToProto(m))
		}
	}

	// Cursor 分页时返回 next_page_token
	switch req.GetPagination().(type) {
	case *adminv1.ListDepartmentsRequest_PageToken:
		if len(depObj) == int(pageSize) && len(depObj) > 0 {
			last := depObj[len(depObj)-1].ID
			tokenData, _ := json.Marshal(last)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}

	return result, nil
}

// DeleteDepartment 删除部门
func (a *KnownAdminAPI) DeleteDepartment(ctx context.Context, req *adminv1.DeleteDepartmentRequest) (*emptypb.Empty, error) {
	empty := &emptypb.Empty{}

	db, err := a.GetLionClient()
	if err != nil {
		return empty, err
	}

	// 检查用户是否有权限操作该部门
	if err := a.checkDepartmentPermission(ctx, db, int(req.Id)); err != nil {
		return empty, err
	}

	deps, err := a.ListDepartments(ctx, &adminv1.ListDepartmentsRequest{})
	if err != nil {
		return empty, err
	}

	hasFound := false

	var checkDep func(childrens []*adminv1.Department) bool
	checkDep = func(childrens []*adminv1.Department) bool {
		for _, c := range childrens {
			// 如果找到匹配的叶子节点，返回 true 提前终止
			if (c.Id == req.Id) && len(c.Children) == 0 {
				return true
			}

			// 递归检查子节点，如果子节点中找到匹配项，立即返回 true
			if checkDep(c.Children) {
				return true
			}
		}

		// 未找到匹配节点
		return false
	}

	hasFound = checkDep(deps.Departments)
	if hasFound {
		// TODO; 还需判断该部门下是否有用户
		/*
			count := a.config.db.Users.Query().Where(users.DepartmentIDEQ(int(req.Id))).CountX(ctx)
			if count > 0 {
				return empty, errs.PermissionDenied(ctx).WithMessage("department has users")
			}

			_, err = a.config.db.Departments.Delete().
				Where(
					departments.ID(int(req.Id)),
				).Exec(ctx)

			return empty, err
		*/
	}

	return empty, errs.PermissionDenied(ctx)
}

// UpdateDepartment 更新部门
func (a *KnownAdminAPI) UpdateDepartment(ctx context.Context, req *adminv1.UpdateDepartmentRequest) (*adminv1.Department, error) {
	result := &adminv1.Department{}

	if req == nil || req.Department == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body department is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限操作该部门
	if err := a.checkDepartmentPermission(ctx, db, int(req.Department.Id)); err != nil {
		return result, err
	}

	// 如果更新了 parent_id，需要检查新父部门的权限
	if req.UpdateMask != nil {
		for _, path := range req.UpdateMask.Paths {
			if path == departments.FieldParentID {
				if req.Department.ParentId != 0 {
					if err := a.checkDepartmentPermission(ctx, db, int(req.Department.ParentId)); err != nil {
						return result, err
					}
				} else {
					// 设置为根部门（parent_id = 0）需要检查用户是否有权限操作根部门
					if err := a.checkDepartmentPermission(ctx, db, 0); err != nil {
						return result, err
					}
				}
			}
		}
	}

	if req.UpdateMask != nil && len(req.UpdateMask.Paths) != 0 {
		x := a.config.db.Departments.Update()

		for _, path := range req.UpdateMask.Paths {
			switch path {
			case departments.FieldCode:
				x.SetCode(req.Department.Code)
			case departments.FieldSortOrder:
				x.SetSortOrder(int(req.Department.SortOrder))
			case departments.FieldParentID:
				if req.Department.ParentId == 0 || req.Department.ParentId == req.Department.Id {
					continue
				}

				x.SetParentID(int(req.Department.ParentId))
			case departments.FieldVisibility:
				x.SetVisibility(int(req.Department.Visibility))
			}
		}

		_, err := x.Where(departments.IDEQ(int(req.Department.Id))).Save(ctx)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// ListDepartmentMembers 获取部门成员（与 proto Membership 定义对齐）
func (a *KnownAdminAPI) ListDepartmentMembers(ctx context.Context, req *adminv1.ListDepartmentMembersRequest) (*adminv1.ListDepartmentMembersResponse, error) {
	result := &adminv1.ListDepartmentMembersResponse{}

	if req.Parent == "" {
		return result, errs.InvalidArgument(ctx).WithMessage("request body parent is empty")
	}

	departmentID, err := strconv.Atoi(req.Parent)
	if err != nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body parent is invalid")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	if err := a.checkDepartmentPermission(ctx, db, departmentID); err != nil {
		return result, err
	}

	pageSize := int(GetPageSize(ctx, req.PageSize))
	memberQuery := db.DepartmentMembers.Query().Where(departmentmembers.DepartmentIDEQ(departmentID))

	// 排序（与 proto order_by 约定一致）
	switch req.GetOrderBy() {
	case "created_at desc", "create_at desc":
		memberQuery = memberQuery.Order(lion.Desc(departmentmembers.FieldCreatedAt))
	case "created_at asc", "create_at asc":
		memberQuery = memberQuery.Order(lion.Asc(departmentmembers.FieldCreatedAt))
	case "member_role asc":
		memberQuery = memberQuery.Order(lion.Asc(departmentmembers.FieldMemberRole))
	case "member_role desc":
		memberQuery = memberQuery.Order(lion.Desc(departmentmembers.FieldMemberRole))
	case "member_status asc":
		memberQuery = memberQuery.Order(lion.Asc(departmentmembers.FieldMemberStatus))
	case "member_status desc":
		memberQuery = memberQuery.Order(lion.Desc(departmentmembers.FieldMemberStatus))
	default:
		memberQuery = memberQuery.Order(lion.Desc(departmentmembers.FieldID))
	}

	totalSize, err := memberQuery.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	// 分页
	switch p := req.GetPagination().(type) {
	case *adminv1.ListDepartmentMembersRequest_Offset:
		memberQuery = memberQuery.Offset(int(p.Offset))
	case *adminv1.ListDepartmentMembersRequest_PageToken:
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
				memberQuery = memberQuery.Where(departmentmembers.IDLT(lastID))
			}
		}
	}

	memberQuery = memberQuery.Limit(pageSize)

	members, err := memberQuery.Select(
		departmentmembers.FieldID,
		departmentmembers.FieldUserID,
		departmentmembers.FieldDepartmentID,
		departmentmembers.FieldMemberRole,
		departmentmembers.FieldMemberStatus,
		departmentmembers.FieldMemberType,
		departmentmembers.FieldDescription,
		departmentmembers.FieldMetadata,
		departmentmembers.FieldCreatedBy,
		departmentmembers.FieldUpdatedBy,
		departmentmembers.FieldCreatedAt,
		departmentmembers.FieldUpdatedAt,
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

	// Cursor 分页时返回 next_page_token
	if _, ok := req.GetPagination().(*adminv1.ListDepartmentMembersRequest_PageToken); ok {
		if len(members) == pageSize && len(members) > 0 {
			lastID := members[len(members)-1].ID
			tokenData, _ := json.Marshal(lastID)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}

	return result, nil
}

// CreateDepartmentMembers 创建部门成员（与 proto Membership 定义对齐）
func (a *KnownAdminAPI) CreateDepartmentMembers(ctx context.Context, req *adminv1.CreateDepartmentMembersRequest) (*adminv1.CreateDepartmentMembersResponse, error) {
	result := &adminv1.CreateDepartmentMembersResponse{}

	if req.DepartmentId == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("department_id is required")
	}
	if len(req.Members) == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("memberships is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	if err := a.checkDepartmentPermission(ctx, db, int(req.DepartmentId)); err != nil {
		return result, err
	}

	var userID int64
	if uid, err := GetUserID(ctx); err == nil {
		userID = uid
	}

	depMembers := make([]*lion.DepartmentMembersCreate, 0, len(req.Members))

	for _, member := range req.Members {
		if member.UserId == 0 {
			return result, errs.InvalidArgument(ctx).WithMessage("membership.user_id is required")
		}

		role := int(adminv1.Membership_MEMBER)
		if member.MemberRole != adminv1.Membership_ROLE_UNSPECIFIED {
			role = int(member.MemberRole)
		}
		status := int(adminv1.Membership_ACTIVE)
		if member.MemberStatus != adminv1.Membership_STATUS_UNSPECIFIED {
			status = int(member.MemberStatus)
		}
		memberType := int(adminv1.Membership_PRIMARY)
		if member.MemberType != adminv1.Membership_MEMBER_TYPE_UNSPECIFIED {
			memberType = int(member.MemberType)
		}

		create := db.DepartmentMembers.Create().
			SetUserID(int(member.UserId)).
			SetDepartmentID(int(req.DepartmentId)).
			SetMemberRole(role).
			SetMemberStatus(status).
			SetMemberType(memberType)
		if member.Description != "" {
			create = create.SetDescription(member.Description)
		}
		if len(member.Metadata) > 0 {
			create = create.SetMetadata(MetadataJSON(member.Metadata))
		}
		if userID != 0 {
			create = create.SetCreatedBy(userID).SetUpdatedBy(userID)
		}
		depMembers = append(depMembers, create)
	}

	_, err = db.DepartmentMembers.CreateBulk(depMembers...).Save(ctx)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// UpdateDepartmentMembers 更新部门成员（按 department_id + user_id 定位，与 proto Membership 对齐）
func (a *KnownAdminAPI) UpdateDepartmentMembers(ctx context.Context, req *adminv1.UpdateDepartmentMembersRequest) (*adminv1.UpdateDepartmentMembersResponse, error) {
	result := &adminv1.UpdateDepartmentMembersResponse{}

	if req.DepartmentId == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("department_id is required")
	}
	if len(req.Members) == 0 {
		return result, nil
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	if err := a.checkDepartmentPermission(ctx, db, int(req.DepartmentId)); err != nil {
		return result, err
	}

	var updatedBy int64
	if uid, err := GetUserID(ctx); err == nil {
		updatedBy = uid
	}

	for _, member := range req.Members {
		if member.UserId == 0 {
			continue
		}

		upd := db.DepartmentMembers.Update().
			Where(
				departmentmembers.DepartmentIDEQ(int(req.DepartmentId)),
				departmentmembers.UserIDEQ(int(member.UserId)),
			)

		if member.MemberRole != adminv1.Membership_ROLE_UNSPECIFIED {
			upd = upd.SetMemberRole(int(member.MemberRole))
		}
		if member.MemberStatus != adminv1.Membership_STATUS_UNSPECIFIED {
			upd = upd.SetMemberStatus(int(member.MemberStatus))
		}
		if member.MemberType != adminv1.Membership_MEMBER_TYPE_UNSPECIFIED {
			upd = upd.SetMemberType(int(member.MemberType))
		}
		// description 允许置空，按请求更新
		upd = upd.SetDescription(member.Description)
		if len(member.Metadata) > 0 {
			upd = upd.SetMetadata(MetadataJSON(member.Metadata))
		}
		if updatedBy != 0 {
			upd = upd.SetUpdatedBy(updatedBy)
		}

		_, err := upd.Save(ctx)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// DeleteDepartmentMember 删除部门成员
func (a *KnownAdminAPI) DeleteDepartmentMember(ctx context.Context, req *adminv1.DeleteDepartmentMemberRequest) (*emptypb.Empty, error) {
	departmentID := req.DepartmentId
	userID := req.UserId

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限操作该部门
	if err := a.checkDepartmentPermission(ctx, db, int(departmentID)); err != nil {
		return nil, err
	}

	_, err = db.DepartmentMembers.Delete().
		Where(
			departmentmembers.UserIDEQ(int(userID)),
			departmentmembers.DepartmentIDEQ(int(departmentID)),
		).
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// 构建部门树
func (a *KnownAdminAPI) buildDepartmentTree(ctx context.Context, dep *lion.Departments) (*adminv1.Department, error) {
	// 查子部门
	children, err := a.config.db.Departments.
		Query().
		Where(departments.ParentIDEQ(dep.ID)).All(ctx)
	if err != nil {
		return nil, err
	}

	pbDep := &adminv1.Department{
		Id:         int64(dep.ID),
		ParentId:   int64(dep.ParentID),
		Code:       dep.Code,
		SortOrder:  int32(dep.SortOrder),
		Visibility: adminv1.Visibility(dep.Visibility),
		Members:    make([]*adminv1.Membership, 0),
	}

	// 递归子部门
	for _, c := range children {
		childTree, err := a.buildDepartmentTree(ctx, c)
		if err != nil {
			return nil, err
		}

		pbDep.Children = append(pbDep.Children, childTree)
	}

	return pbDep, nil
}

// 递归获取所有子部门 ID
func (a *KnownAdminAPI) getAllSubDeptIDs(ctx context.Context, deptID int) ([]int, error) {
	var ids []int
	ids = append(ids, deptID)

	// 查询子部门
	children, err := a.config.db.Departments.
		Query().
		Select(departments.FieldID).
		Where(departments.ParentID(deptID)).
		All(ctx)
	if err != nil {
		return nil, err
	}

	// 递归收集
	for _, child := range children {
		subIDs, err := a.getAllSubDeptIDs(ctx, child.ID)
		if err != nil {
			return nil, err
		}
		ids = append(ids, subIDs...)
	}
	return ids, nil
}

// checkDepartmentPermission 检查用户是否有权限操作指定部门
// 权限检查逻辑：
// 1. 检查用户的角色是否有该部门的数据范围权限
// 2. 如果设置了 is_recursive，还需要检查父部门权限（递归检查）
// 数据范围表已注释：不再按角色数据范围校验，仅校验用户是否有角色
func (a *KnownAdminAPI) checkDepartmentPermission(ctx context.Context, db *lion.Client, departmentID int) error {
	userRoleIDs, err := a.getUserRoleID(ctx)
	if err != nil {
		return err
	}
	if len(userRoleIDs) == 0 {
		return errs.PermissionDenied(ctx).WithMessage("user has no roles")
	}
	return nil
}

// checkDepartmentPermissionTx 检查用户是否有权限操作指定部门（事务版本）
// 数据范围表已注释：不再按角色数据范围校验，仅校验用户是否有角色
func (a *KnownAdminAPI) checkDepartmentPermissionTx(ctx context.Context, tx *lion.Tx, departmentID int) error {
	userRoleIDs, err := a.getUserRoleID(ctx)
	if err != nil {
		return err
	}
	if len(userRoleIDs) == 0 {
		return errs.PermissionDenied(ctx).WithMessage("user has no roles")
	}
	return nil
}

// getDepartmentAncestorIDs 递归获取部门的所有祖先部门ID（包括父部门、祖父部门等）
func (a *KnownAdminAPI) getDepartmentAncestorIDs(ctx context.Context, db *lion.Client, departmentID int) ([]int, error) {
	var ancestorIDs []int

	currentID := departmentID
	for {
		// 查询当前部门的父部门
		dept, err := db.Departments.Query().
			Select(departments.FieldID, departments.FieldParentID).
			Where(departments.IDEQ(currentID)).
			Only(ctx)
		if err != nil {
			// 如果查询失败或不存在，停止递归
			break
		}

		// 如果没有父部门（parent_id = 0），停止递归
		if dept.ParentID == 0 {
			break
		}

		// 添加父部门ID到列表
		ancestorIDs = append(ancestorIDs, dept.ParentID)

		// 继续向上查找
		currentID = dept.ParentID
	}

	return ancestorIDs, nil
}

// getAncestorIDsInMemory 在内存中沿 parent 链求祖先 ID 列表，无 DB 调用
func getAncestorIDsInMemory(depByID map[int]*lion.Departments, departmentID int) []int {
	var ancestors []int
	currentID := departmentID
	for {
		d := depByID[currentID]
		if d == nil || d.ParentID == 0 {
			break
		}
		ancestors = append(ancestors, d.ParentID)
		currentID = d.ParentID
	}
	return ancestors
}

// getAllSubDeptIDsInMemory 在内存中 BFS 求某部门及其全部子部门 ID，无 DB 调用
func getAllSubDeptIDsInMemory(childrenByParentID map[int][]int, deptID int) []int {
	var ids []int
	queue := []int{deptID}
	for len(queue) > 0 {
		id := queue[0]
		queue = queue[1:]
		ids = append(ids, id)
		queue = append(queue, childrenByParentID[id]...)
	}
	return ids
}

// getVisibleDepartmentIDs 根据可见性策略过滤部门 ID
// 规则：GLOBAL 全员可见；SUBTREE 本部门及上级节点可见下属（不管下级节点设置的可见性，下属均可见）；LOCAL 仅本部门成员可见；RESTRICTED/SPECIFIC 仅创建者或负责人可见
func (a *KnownAdminAPI) getVisibleDepartmentIDs(ctx context.Context, db *lion.Client, candidateIDs []int) ([]int, error) {
	userID, err := GetUserID(ctx)
	if err != nil || userID == 0 {
		return nil, nil
	}

	// 用户所在部门及担任负责人/经理的部门（一次查询后拆分，避免两次 DB 往返）
	udList, err := db.DepartmentMembers.Query().
		Where(departmentmembers.UserIDEQ(int(userID))).
		Select(departmentmembers.FieldDepartmentID, departmentmembers.FieldMemberRole).
		All(ctx)
	if err != nil {
		return nil, err
	}
	userDeptIDSet := make(map[int]struct{})
	managedDeptIDSet := make(map[int]struct{})
	for _, ud := range udList {
		userDeptIDSet[ud.DepartmentID] = struct{}{}
		if ud.MemberRole == int(adminv1.Membership_OWNER.Number()) || ud.MemberRole == int(adminv1.Membership_MANAGER.Number()) {
			managedDeptIDSet[ud.DepartmentID] = struct{}{}
		}
	}

	// 候选部门的 ID、父级、可见性、创建者
	deps, err := db.Departments.Query().
		Where(departments.IDIn(candidateIDs...)).
		Select(
			departments.FieldID,
			departments.FieldParentID,
			departments.FieldVisibility,
			departments.FieldCreatedBy,
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	// 内存建表：避免在循环内对每个 SUBTREE 部门做 N 次 DB 查询（祖先链、子树）
	depByID := make(map[int]*lion.Departments)
	childrenByParentID := make(map[int][]int)
	for i := range deps {
		depByID[deps[i].ID] = deps[i]
		pid := deps[i].ParentID
		childrenByParentID[pid] = append(childrenByParentID[pid], deps[i].ID)
	}

	var visibleIDs []int
	for _, d := range deps {
		vis := adminv1.Visibility(d.Visibility)
		switch vis {
		case adminv1.Visibility_VISIBILITY_UNSPECIFIED, adminv1.Visibility_VISIBILITY_GLOBAL:
			visibleIDs = append(visibleIDs, d.ID)
			continue
		case adminv1.Visibility_VISIBILITY_SUBTREE:
			// 本部门及上级节点可见其下属：用户在该部门或在该部门的任一祖先部门（内存遍历，无 DB）
			ancestors := getAncestorIDsInMemory(depByID, d.ID)
			if _, ok := userDeptIDSet[d.ID]; ok {
				visibleIDs = append(visibleIDs, d.ID)
				continue
			}
			for _, aid := range ancestors {
				if _, ok := userDeptIDSet[aid]; ok {
					visibleIDs = append(visibleIDs, d.ID)
					break
				}
			}
			continue
		case adminv1.Visibility_VISIBILITY_LOCAL:
			if _, ok := userDeptIDSet[d.ID]; ok {
				visibleIDs = append(visibleIDs, d.ID)
			}
			continue
		case adminv1.Visibility_VISIBILITY_RESTRICTED, adminv1.Visibility_VISIBILITY_SPECIFIC:
			// 仅创建者或负责人可见
			if d.CreatedBy == userID {
				visibleIDs = append(visibleIDs, d.ID)
				continue
			}
			if _, ok := managedDeptIDSet[d.ID]; ok {
				visibleIDs = append(visibleIDs, d.ID)
			}
			continue
		default:
			visibleIDs = append(visibleIDs, d.ID)
		}
	}

	// SUBTREE 向下递归：成员处于相同节点或上级节点可见其下属节点；下级节点设置的可见性（LOCAL/RESTRICTED 等）在此场景下忽略，下属均对上级成员可见
	visibleSet := make(map[int]struct{})
	for _, id := range visibleIDs {
		visibleSet[id] = struct{}{}
	}
	// 从用户所属的部门出发，若该部门为 SUBTREE 或未指定，则加入该部门及全部下属（内存 BFS，无递归 DB）
	for userDeptID := range userDeptIDSet {
		d := depByID[userDeptID]
		if d == nil {
			continue
		}
		vis := adminv1.Visibility(d.Visibility)
		if vis != adminv1.Visibility_VISIBILITY_SUBTREE && vis != adminv1.Visibility_VISIBILITY_UNSPECIFIED {
			continue
		}
		subIDs := getAllSubDeptIDsInMemory(childrenByParentID, userDeptID)
		for _, id := range subIDs {
			if _, ok := visibleSet[id]; !ok {
				visibleSet[id] = struct{}{}
				visibleIDs = append(visibleIDs, id)
			}
		}
	}
	// 已可见且可见性为 SUBTREE 的部门，其所有下属也加入（内存 BFS）
	for _, d := range deps {
		if adminv1.Visibility(d.Visibility) != adminv1.Visibility_VISIBILITY_SUBTREE {
			continue
		}
		if _, ok := visibleSet[d.ID]; !ok {
			continue
		}
		subIDs := getAllSubDeptIDsInMemory(childrenByParentID, d.ID)
		for _, id := range subIDs {
			if _, ok := visibleSet[id]; !ok {
				visibleSet[id] = struct{}{}
				visibleIDs = append(visibleIDs, id)
			}
		}
	}
	return visibleIDs, nil
}

// getDepartmentAncestorIDsTx 递归获取部门的所有祖先部门ID（事务版本）
func (a *KnownAdminAPI) getDepartmentAncestorIDsTx(ctx context.Context, tx *lion.Tx, departmentID int) ([]int, error) {
	var ancestorIDs []int

	currentID := departmentID
	for {
		// 查询当前部门的父部门
		dept, err := tx.Departments.Query().
			Select(departments.FieldID, departments.FieldParentID).
			Where(departments.IDEQ(currentID)).
			Only(ctx)
		if err != nil {
			// 如果查询失败或不存在，停止递归
			break
		}

		// 如果没有父部门（parent_id = 0），停止递归
		if dept.ParentID == 0 {
			break
		}

		// 添加父部门ID到列表
		ancestorIDs = append(ancestorIDs, dept.ParentID)

		// 继续向上查找
		currentID = dept.ParentID
	}

	return ancestorIDs, nil
}
