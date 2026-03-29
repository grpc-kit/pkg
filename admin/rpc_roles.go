package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/grouproles"

	// 数据范围表已注释，同步取消依赖
	// "github.com/grpc-kit/pkg/lion/roledataranges"
	"github.com/grpc-kit/pkg/lion/rolepermissions"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/schema"
	"github.com/grpc-kit/pkg/lion/userroles"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// getAllChildRoleIDs 递归获取所有子角色ID
func (a *KnownAdminAPI) getAllChildRoleIDs(ctx context.Context, db *lion.Client, parentIDs []int) ([]int, error) {
	if len(parentIDs) == 0 {
		return []int{}, nil
	}

	// 查询所有子角色
	childRoles, err := db.Roles.Query().
		Select(roles.FieldID, roles.FieldParentID).
		Where(roles.ParentIDIn(parentIDs...)).
		All(ctx)
	if err != nil {
		return nil, err
	}

	if len(childRoles) == 0 {
		return []int{}, nil
	}

	// 收集子角色ID
	childIDs := make([]int, 0, len(childRoles))
	for _, child := range childRoles {
		childIDs = append(childIDs, child.ID)
	}

	// 递归获取子角色的子角色
	grandChildIDs, err := a.getAllChildRoleIDs(ctx, db, childIDs)
	if err != nil {
		return nil, err
	}

	// 合并所有子角色ID
	allChildIDs := append(childIDs, grandChildIDs...)
	return allChildIDs, nil
}

// checkRolePermission 检查用户是否有权限操作指定角色
// 返回 true 表示用户拥有该角色或其子角色，可以操作
func (a *KnownAdminAPI) checkRolePermission(ctx context.Context, db *lion.Client, roleID int) error {
	// 获取当前用户的角色ID列表
	userRoleIDs, err := a.getUserRoleID(ctx)
	if err != nil {
		return err
	}

	if len(userRoleIDs) == 0 {
		return errs.PermissionDenied(ctx).WithMessage("user has no roles")
	}

	// 检查目标角色是否就是用户拥有的角色之一
	for _, userRoleID := range userRoleIDs {
		if userRoleID == roleID {
			return nil
		}
	}

	// 递归获取所有子角色ID
	allChildRoleIDs, err := a.getAllChildRoleIDs(ctx, db, userRoleIDs)
	if err != nil {
		return err
	}

	// 检查目标角色是否是用户角色的子角色
	for _, childRoleID := range allChildRoleIDs {
		if childRoleID == roleID {
			return nil
		}
	}

	// 没有权限
	return errs.PermissionDenied(ctx).WithMessage("user does not have permission to access this role")
}

// checkParentRolePermission 检查用户是否有权限将新角色创建为指定父角色的子角色
// 如果 parentID 为 0，表示创建根角色，需要检查用户是否有根角色权限
func (a *KnownAdminAPI) checkParentRolePermission(ctx context.Context, db *lion.Client, parentID int64) error {
	if parentID == 0 {
		return nil
	}

	// 检查用户是否有权限操作父角色
	return a.checkRolePermission(ctx, db, int(parentID))
}

func (a *KnownAdminAPI) checkRootRoleConstraint(ctx context.Context, db *lion.Client, roleID int, roleCode string, parentID int64) error {
	if parentID != 0 {
		return nil
	}

	superadminCode := seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN)
	if roleCode != superadminCode {
		return errs.InvalidArgument(ctx).WithMessage("only superadmin role can be root role")
	}

	query := db.Roles.Query().Where(roles.ParentIDEQ(0))
	if roleID > 0 {
		query = query.Where(roles.IDNEQ(roleID))
	}

	count, err := query.Count(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		return errs.InvalidArgument(ctx).WithMessage("root role already exists")
	}
	return nil
}

// ListRoles 获取角色列表，默认返回树状结构
// 仅返回当前用户拥有的角色及其所有子角色
func (a *KnownAdminAPI) ListRoles(ctx context.Context, req *adminv1.ListRolesRequest) (*adminv1.ListRolesResponse, error) {
	result := &adminv1.ListRolesResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 获取当前用户的角色ID列表
	userRoleIDs, err := a.getUserRoleID(ctx)
	if err != nil {
		return nil, err
	}

	if len(userRoleIDs) == 0 {
		// 用户没有任何角色，返回空列表
		result.Roles = []*adminv1.Role{}
		result.TotalSize = 0
		return result, nil
	}

	// 递归获取所有子角色ID
	allChildRoleIDs, err := a.getAllChildRoleIDs(ctx, db, userRoleIDs)
	if err != nil {
		return nil, err
	}

	// 合并用户角色ID和所有子角色ID
	allowedRoleIDs := make(map[int]bool)
	for _, id := range userRoleIDs {
		allowedRoleIDs[id] = true
	}
	for _, id := range allChildRoleIDs {
		allowedRoleIDs[id] = true
	}

	// 转换为切片用于查询
	allowedRoleIDsSlice := make([]int, 0, len(allowedRoleIDs))
	for id := range allowedRoleIDs {
		allowedRoleIDsSlice = append(allowedRoleIDsSlice, id)
	}

	// 添加 parent_id 字段到查询字段列表
	defaultSelect := []string{
		roles.FieldID,
		roles.FieldParentID,
		roles.FieldCode,
		roles.FieldDisplayName,
		roles.FieldRoleType,
		roles.FieldRoleStatus,
		roles.FieldSortOrder,
		roles.FieldDescription,
		roles.FieldCreatedAt,
		roles.FieldUpdatedAt,
	}

	roleQuery := db.Roles.Query().
		Where(roles.IDIn(allowedRoleIDsSlice...))

	// 查找用户并实现分页
	pageSize := GetPageSize(ctx, req.PageSize)

	// OrderBy
	if req.GetOrderBy() != "" {
		switch req.GetOrderBy() {
		case "create_time desc":
			roleQuery = roleQuery.Order(lion.Desc(roles.FieldCreatedAt))
		case "create_time asc":
			roleQuery = roleQuery.Order(lion.Asc(roles.FieldCreatedAt))
		default:
			roleQuery = roleQuery.Order(lion.Desc(roles.FieldID))
		}
	} else {
		// 默认按 sort_order 升序，然后按 ID 升序
		roleQuery = roleQuery.Order(lion.Asc(roles.FieldSortOrder), lion.Asc(roles.FieldID))
	}

	totalSize, err := roleQuery.Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	switch p := req.GetPagination().(type) {
	case *adminv1.ListRolesRequest_Offset:
		// Offset 分页
		roleQuery = roleQuery.Offset(int(p.Offset))
	case *adminv1.ListRolesRequest_PageToken:
		// TODO; Cursor 分页
	}

	roleQuery = roleQuery.Limit(int(pageSize))

	rl, err := roleQuery.Select(defaultSelect...).All(ctx)
	if err != nil {
		return nil, err
	}

	// 构建角色映射和树状结构
	roleMap := make(map[int64]*adminv1.Role)
	var roots []*adminv1.Role

	// 首先将所有角色转换为 protobuf 格式并存入 map
	for _, r := range rl {
		role := &adminv1.Role{
			Id:          int64(r.ID),
			ParentId:    int64(r.ParentID),
			Code:        r.Code,
			DisplayName: r.DisplayName,
			Type:        adminv1.Role_Type(r.RoleType),
			Status:      adminv1.Role_Status(r.RoleStatus),
			SortOrder:   int32(r.SortOrder),
			Description: r.Description,
			CreatedAt:   timestamppb.New(r.CreatedAt),
			UpdatedAt:   timestamppb.New(r.UpdatedAt),
			Children:    make([]*adminv1.Role, 0),
		}

		roleMap[int64(r.ID)] = role
	}

	// 构建父子关系
	for _, role := range roleMap {
		if role.ParentId != 0 {
			if parent, ok := roleMap[role.ParentId]; ok {
				parent.Children = append(parent.Children, role)
			} else {
				// 父节点不在当前查询结果中，作为根节点处理
				roots = append(roots, role)
			}
		} else {
			// parent_id 为 0，是根节点
			roots = append(roots, role)
		}
	}

	// 对根节点排序
	sort.Slice(roots, func(i, j int) bool {
		if roots[i].SortOrder != roots[j].SortOrder {
			return roots[i].SortOrder < roots[j].SortOrder
		}
		return roots[i].Id < roots[j].Id
	})

	// 递归排序子节点
	a.sortRoleChildren(roots)

	result.Roles = roots

	return result, nil
}

// sortRoleChildren 递归排序角色的子节点
func (a *KnownAdminAPI) sortRoleChildren(roles []*adminv1.Role) {
	for _, role := range roles {
		if len(role.Children) > 0 {
			sort.Slice(role.Children, func(i, j int) bool {
				if role.Children[i].SortOrder != role.Children[j].SortOrder {
					return role.Children[i].SortOrder < role.Children[j].SortOrder
				}
				return role.Children[i].Id < role.Children[j].Id
			})
			// 递归排序子节点的子节点
			a.sortRoleChildren(role.Children)
		}
	}
}

// roleMembersToGroupMembersListReq 将 ListRoleMembers 请求映射为 ListGroupMembers 请求，
// 以便复用 listGroupMembersFromRole（user_roles → Membership）逻辑。
func roleMembersToGroupMembersListReq(req *adminv1.ListRoleMembersRequest) *adminv1.ListGroupMembersRequest {
	g := &adminv1.ListGroupMembersRequest{
		Parent:   req.GetParent(),
		PageSize: req.GetPageSize(),
		Filter:   req.GetFilter(),
		OrderBy:  req.GetOrderBy(),
	}
	switch p := req.GetPagination().(type) {
	case *adminv1.ListRoleMembersRequest_PageToken:
		g.Pagination = &adminv1.ListGroupMembersRequest_PageToken{PageToken: p.PageToken}
	case *adminv1.ListRoleMembersRequest_Offset:
		g.Pagination = &adminv1.ListGroupMembersRequest_Offset{Offset: p.Offset}
	}
	return g
}

// ListRoleMembers 获取角色成员列表（与 ListGroupMembers 中基于 user_roles 的成员结构一致）
func (a *KnownAdminAPI) ListRoleMembers(ctx context.Context, req *adminv1.ListRoleMembersRequest) (*adminv1.ListRoleMembersResponse, error) {
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	roleID, err := strconv.Atoi(req.GetParent())
	if err != nil {
		return nil, err
	}

	if err := a.checkRolePermission(ctx, db, roleID); err != nil {
		return nil, err
	}

	gr, err := a.listGroupMembersFromRole(ctx, roleMembersToGroupMembersListReq(req), db, roleID)
	if err != nil {
		return nil, err
	}
	return &adminv1.ListRoleMembersResponse{
		Members:       gr.GetMembers(),
		NextPageToken: gr.GetNextPageToken(),
		TotalSize:     gr.GetTotalSize(),
	}, nil
}

// DeleteRoleMember 移除角色下的成员（user_roles 一行）
func (a *KnownAdminAPI) DeleteRoleMember(ctx context.Context, req *adminv1.DeleteRoleMemberRequest) (*emptypb.Empty, error) {
	empty := &emptypb.Empty{}

	roleID, err := strconv.Atoi(req.Parent)
	if err != nil {
		return empty, err
	}

	db, err := a.GetLionClient()
	if err != nil {
		return empty, err
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, roleID); err != nil {
		return nil, err
	}

	_, err = db.UserRoles.Delete().
		Where(
			userroles.RoleID(roleID),
			userroles.UserIDEQ(int(req.UserId)),
		).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return empty, nil
}

// CreateRole 创建角色
func (a *KnownAdminAPI) CreateRole(ctx context.Context, req *adminv1.CreateRoleRequest) (*adminv1.Role, error) {
	result := &adminv1.Role{}

	if req.Role == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body role is nil")
	}

	code, err := schema.EnsureCode(req.Role.Code)
	if err != nil {
		return result, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	req.Role.Code = code

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限创建该父角色的子角色
	if err := a.checkParentRolePermission(ctx, db, req.Role.ParentId); err != nil {
		return nil, err
	}
	if err := a.checkRootRoleConstraint(ctx, db, 0, req.Role.Code, req.Role.ParentId); err != nil {
		return nil, err
	}

	createBuilder := db.Roles.Create().
		SetCode(req.Role.Code).
		SetDisplayName(req.Role.DisplayName).
		SetDescription(req.Role.Description).
		SetSortOrder(int(req.Role.SortOrder))

	// 设置 parent_id（如果提供）
	if req.Role.ParentId > 0 {
		createBuilder.SetParentID(int(req.Role.ParentId))
	}

	// 获取创建者用户 ID
	userID, _ := GetUserID(ctx)
	if userID > 0 {
		createBuilder.SetCreatedBy(userID).SetUpdatedBy(userID)
	}

	role, err := createBuilder.Save(ctx)
	if err != nil {
		return result, err
	}

	result = &adminv1.Role{
		Id:          int64(role.ID),
		ParentId:    int64(role.ParentID),
		Code:        role.Code,
		DisplayName: role.DisplayName,
		Description: role.Description,
		SortOrder:   int32(role.SortOrder),
		Type:        adminv1.Role_Type(role.RoleType),
		Status:      adminv1.Role_Status(role.RoleStatus),
		CreatedBy:   role.CreatedBy,
		UpdatedBy:   role.UpdatedBy,
		CreatedAt:   timestamppb.New(role.CreatedAt),
		UpdatedAt:   timestamppb.New(role.UpdatedAt),
		Children:    make([]*adminv1.Role, 0),
	}

	return result, nil
}

// GetRole 获取角色详情
func (a *KnownAdminAPI) GetRole(ctx context.Context, req *adminv1.GetRoleRequest) (*adminv1.Role, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 查询角色信息
	role, err := db.Roles.Query().Select(
		roles.FieldID,
		roles.FieldParentID,
		roles.FieldCode,
		roles.FieldDisplayName,
		roles.FieldRoleType,
		roles.FieldRoleStatus,
		roles.FieldSortOrder,
		roles.FieldDescription,
		roles.FieldCreatedBy,
		roles.FieldUpdatedBy,
		roles.FieldCreatedAt,
		roles.FieldUpdatedAt,
	).Where(
		roles.ID(int(req.Id)),
	).Only(ctx)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role not found")
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, role.ID); err != nil {
		return nil, err
	}

	result := &adminv1.Role{
		Id:          int64(role.ID),
		ParentId:    int64(role.ParentID),
		Code:        role.Code,
		DisplayName: role.DisplayName,
		Description: role.Description,
		SortOrder:   int32(role.SortOrder),
		Type:        adminv1.Role_Type(role.RoleType),
		Status:      adminv1.Role_Status(role.RoleStatus),
		CreatedBy:   role.CreatedBy,
		UpdatedBy:   role.UpdatedBy,
		CreatedAt:   timestamppb.New(role.CreatedAt),
		UpdatedAt:   timestamppb.New(role.UpdatedAt),
		Children:    make([]*adminv1.Role, 0),
	}

	return result, nil
}

// DeleteRole 删除角色
func (a *KnownAdminAPI) DeleteRole(ctx context.Context, req *adminv1.DeleteRoleRequest) (*emptypb.Empty, error) {
	// 涉及的几个角色表均不能存在关联

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.Id)); err != nil {
		return nil, err
	}

	if db.GroupRoles.Query().Where(grouproles.RoleIDEQ(int(req.Id))).CountX(ctx) > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role has group")
	}

	// 数据范围表已注释，同步取消依赖
	// if db.RoleDataRanges.Query().Where(roledataranges.RoleIDEQ(int(req.Id))).CountX(ctx) > 0 {
	// 	return nil, errs.InvalidArgument(ctx).WithMessage("role has department")
	// }

	if db.RolePermissions.Query().Where(rolepermissions.RoleIDEQ(int(req.Id))).CountX(ctx) > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role has permission")
	}

	if db.RolePermissions.Query().Where(rolepermissions.RoleIDEQ(int(req.Id))).CountX(ctx) > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role has resource")
	}

	if db.UserRoles.Query().Where(userroles.RoleIDEQ(int(req.Id))).CountX(ctx) > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role has user")
	}

	_, err = db.Roles.Delete().Where(roles.ID(int(req.Id))).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// UpdateRole 更新角色
func (a *KnownAdminAPI) UpdateRole(ctx context.Context, req *adminv1.UpdateRoleRequest) (*adminv1.Role, error) {
	result := &adminv1.Role{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.Role.Id)); err != nil {
		return nil, err
	}

	currentRole, err := db.Roles.Query().
		Select(roles.FieldID, roles.FieldCode, roles.FieldParentID).
		Where(roles.ID(int(req.Role.Id))).
		Only(ctx)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role not found")
	}

	if req.UpdateMask != nil && len(req.UpdateMask.Paths) != 0 {
		x := db.Roles.Update()

		// 获取更新者用户 ID
		userID, _ := GetUserID(ctx)
		nextParentID := int64(currentRole.ParentID)
		nextCode := currentRole.Code

		for _, path := range req.UpdateMask.Paths {
			switch path {
			case roles.FieldCode:
				x.SetCode(req.Role.Code)
				nextCode = req.Role.Code
			case roles.FieldParentID:
				// 更新 parent_id，需要检查新父角色的权限
				if err := a.checkParentRolePermission(ctx, db, req.Role.ParentId); err != nil {
					return nil, err
				}
				if req.Role.ParentId == req.Role.Id {
					return nil, errs.InvalidArgument(ctx).WithMessage("parent_id cannot be self")
				}
				if req.Role.ParentId > 0 {
					allChildRoleIDs, err := a.getAllChildRoleIDs(ctx, db, []int{int(req.Role.Id)})
					if err != nil {
						return nil, err
					}
					for _, childID := range allChildRoleIDs {
						if int64(childID) == req.Role.ParentId {
							return nil, errs.InvalidArgument(ctx).WithMessage("parent_id cannot be descendant role")
						}
					}
				}
				x.SetParentID(int(req.Role.ParentId))
				nextParentID = req.Role.ParentId
			case roles.FieldSortOrder:
				x.SetSortOrder(int(req.Role.SortOrder))
			case roles.FieldDescription:
				x.SetDescription(req.Role.Description)
			case roles.FieldDisplayName:
				x.SetDisplayName(req.Role.DisplayName)
			}
		}
		if err := a.checkRootRoleConstraint(ctx, db, int(req.Role.Id), nextCode, nextParentID); err != nil {
			return nil, err
		}

		// 更新 updated_by
		if userID > 0 {
			x.SetUpdatedBy(userID)
		}

		save, err := x.Where(roles.ID(int(req.Role.Id))).Save(ctx)
		if err != nil {
			return nil, err
		}

		a.logger.Infof("update role save: %v, req id: %v", save, req.Role.Id)

		// 查询更新后的角色信息，包含 parent_id
		q, err := db.Roles.Query().Select(
			roles.FieldID,
			roles.FieldParentID,
			roles.FieldCode,
			roles.FieldDisplayName,
			roles.FieldRoleType,
			roles.FieldRoleStatus,
			roles.FieldSortOrder,
			roles.FieldDescription,
			roles.FieldCreatedBy,
			roles.FieldUpdatedBy,
			roles.FieldCreatedAt,
			roles.FieldUpdatedAt,
		).Where(
			roles.ID(int(req.Role.Id)),
		).Only(ctx)
		if err != nil {
			return nil, err
		}

		result = &adminv1.Role{
			Id:          int64(q.ID),
			ParentId:    int64(q.ParentID),
			Code:        q.Code,
			DisplayName: q.DisplayName,
			Description: q.Description,
			SortOrder:   int32(q.SortOrder),
			Type:        adminv1.Role_Type(q.RoleType),
			Status:      adminv1.Role_Status(q.RoleStatus),
			CreatedBy:   q.CreatedBy,
			UpdatedBy:   q.UpdatedBy,
			CreatedAt:   timestamppb.New(q.CreatedAt),
			UpdatedAt:   timestamppb.New(q.UpdatedAt),
			Children:    make([]*adminv1.Role, 0),
		}
	}

	return result, nil
}

func membershipMetadataToJSON(md map[string]string) (string, error) {
	if len(md) == 0 {
		return "", nil
	}
	b, err := json.Marshal(md)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func applyMembershipToUserRolesCreate(cb *lion.UserRolesCreate, m *adminv1.Membership) (*lion.UserRolesCreate, error) {
	cb = cb.SetMemberRole(int(m.GetMemberRole())).
		SetMemberStatus(int(m.GetMemberStatus())).
		SetMemberType(int(m.GetMemberType())).
		SetDescription(m.GetDescription())
	if m.GetExpiredAt() != nil {
		cb = cb.SetExpiredAt(m.GetExpiredAt().AsTime())
	}
	meta, err := membershipMetadataToJSON(m.GetMetadata())
	if err != nil {
		return nil, err
	}
	if meta != "" {
		cb = cb.SetMetadata(meta)
	}
	return cb, nil
}

func applyMembershipToUserRolesUpdate(ur *lion.UserRolesUpdateOne, m *adminv1.Membership) (*lion.UserRolesUpdateOne, error) {
	ur = ur.SetMemberRole(int(m.GetMemberRole())).
		SetMemberStatus(int(m.GetMemberStatus())).
		SetMemberType(int(m.GetMemberType())).
		SetDescription(m.GetDescription())
	if m.GetExpiredAt() != nil {
		ur = ur.SetExpiredAt(m.GetExpiredAt().AsTime())
	} else {
		ur = ur.ClearExpiredAt()
	}
	meta, err := membershipMetadataToJSON(m.GetMetadata())
	if err != nil {
		return nil, err
	}
	if meta == "" {
		ur = ur.ClearMetadata()
	} else {
		ur = ur.SetMetadata(meta)
	}
	return ur, nil
}

func (a *KnownAdminAPI) userRoleForRoleMemberUpdate(ctx context.Context, db *lion.Client, roleID int, m *adminv1.Membership) (*lion.UserRoles, error) {
	if m.GetId() > 0 {
		ur, err := db.UserRoles.Get(ctx, int(m.GetId()))
		if err != nil {
			if lion.IsNotFound(err) {
				return nil, errs.NotFound(ctx).WithMessage("user role not found")
			}
			return nil, err
		}
		if ur.RoleID != roleID {
			return nil, errs.InvalidArgument(ctx).WithMessage("member id does not belong to this role")
		}
		if m.GetUserId() > 0 && int(m.GetUserId()) != ur.UserID {
			return nil, errs.InvalidArgument(ctx).WithMessage("user_id does not match member record")
		}
		return ur, nil
	}
	if m.GetUserId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("member user_id or id is required")
	}
	ur, err := db.UserRoles.Query().
		Where(userroles.RoleIDEQ(roleID), userroles.UserIDEQ(int(m.GetUserId()))).
		Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("user role membership not found")
		}
		return nil, err
	}
	return ur, nil
}

// CreateRoleMembers 批量添加角色成员（与 CreateGroupMembers REST 形态一致）
func (a *KnownAdminAPI) CreateRoleMembers(ctx context.Context, req *adminv1.CreateRoleMembersRequest) (*adminv1.CreateRoleMembersResponse, error) {
	result := &adminv1.CreateRoleMembersResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	roleID, err := strconv.Atoi(req.GetParent())
	if err != nil {
		return nil, err
	}

	if err := a.checkRolePermission(ctx, db, roleID); err != nil {
		return nil, err
	}

	if len(req.GetMembers()) == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("members is empty")
	}

	for _, m := range req.GetMembers() {
		uid := m.GetUserId()
		if uid == 0 {
			continue
		}
		cb := db.UserRoles.Create().SetRoleID(roleID).SetUserID(int(uid))
		cb, err = applyMembershipToUserRolesCreate(cb, m)
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
		}
		if v, err := GetUserID(ctx); err == nil {
			cb = cb.SetCreatedBy(v).SetUpdatedBy(v)
		}
		if _, err := cb.Save(ctx); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// UpdateRoleMembers 批量更新角色下成员（PATCH .../roles/{parent}/members）
func (a *KnownAdminAPI) UpdateRoleMembers(ctx context.Context, req *adminv1.UpdateRoleMembersRequest) (*adminv1.UpdateRoleMembersResponse, error) {
	result := &adminv1.UpdateRoleMembersResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	roleID, err := strconv.Atoi(req.GetParent())
	if err != nil {
		return nil, err
	}

	if err := a.checkRolePermission(ctx, db, roleID); err != nil {
		return nil, err
	}

	if len(req.GetMembers()) == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("members is empty")
	}

	var actor int64
	if v, err := GetUserID(ctx); err == nil {
		actor = v
	}

	for _, m := range req.GetMembers() {
		ur, err := a.userRoleForRoleMemberUpdate(ctx, db, roleID, m)
		if err != nil {
			return nil, err
		}
		upd := ur.Update()
		upd, err = applyMembershipToUserRolesUpdate(upd, m)
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
		}
		if actor != 0 {
			upd = upd.SetUpdatedBy(actor)
		}
		if _, err := upd.Save(ctx); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// CreateRolePermissions 为角色关联权限
func (a *KnownAdminAPI) CreateRolePermissions(ctx context.Context, req *adminv1.CreateRolePermissionsRequest) (*adminv1.CreateRolePermissionsResponse, error) {
	result := &adminv1.CreateRolePermissionsResponse{}

	if req.RoleId == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("role_id is required")
	}

	if len(req.Permissions) == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("permissions list is empty")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.RoleId)); err != nil {
		return nil, err
	}

	// 获取创建者用户 ID
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	// 检查角色是否存在
	_, err = db.Roles.Get(ctx, int(req.RoleId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role not found")
	}

	// 收集有效的权限 IDs 并验证每个权限是否存在
	permissionIDs := make([]int, 0, len(req.Permissions))
	permissionMap := make(map[int64]*adminv1.Permission)

	for _, perm := range req.Permissions {
		if perm.Id == 0 {
			continue
		}

		// 检查权限是否存在
		dbPermission, err := db.Permissions.Get(ctx, int(perm.Id))
		if err != nil {
			// 如果某个权限不存在，可以选择跳过或返回错误
			// 这里选择跳过不存在的权限
			continue
		}

		permissionIDs = append(permissionIDs, dbPermission.ID)
		// 保存权限信息以便后续返回
		permissionMap[perm.Id] = &adminv1.Permission{
			Id:          int64(dbPermission.ID),
			Code:        dbPermission.Code,
			DisplayName: dbPermission.DisplayName,
			Description: dbPermission.Description,
		}
	}

	if len(permissionIDs) == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("no valid permissions found")
	}

	// 检查是否已存在关联关系，如果存在则跳过
	existingRolePermissions, err := db.RolePermissions.Query().
		Where(
			rolepermissions.RoleIDEQ(int(req.RoleId)),
			rolepermissions.PermissionIDIn(permissionIDs...),
		).
		All(ctx)
	if err != nil {
		return nil, err
	}

	// 构建已存在的 permission ID 集合
	existingPermissionIDSet := make(map[int]bool)
	for _, rp := range existingRolePermissions {
		existingPermissionIDSet[rp.PermissionID] = true
	}

	// 过滤出需要创建的 permission IDs（排除已存在的）
	permissionsToCreate := make([]int, 0)
	for _, permissionID := range permissionIDs {
		if !existingPermissionIDSet[permissionID] {
			permissionsToCreate = append(permissionsToCreate, permissionID)
		}
	}

	// 批量创建关联关系
	if len(permissionsToCreate) > 0 {
		allRolePermissions := make([]*lion.RolePermissionsCreate, 0, len(permissionsToCreate))

		for _, permissionID := range permissionsToCreate {
			rp := db.RolePermissions.Create().
				SetRoleID(int(req.RoleId)).
				SetPermissionID(permissionID).
				SetCreatedBy(userID).
				SetUpdatedBy(userID)

			allRolePermissions = append(allRolePermissions, rp)
		}

		_, err = db.RolePermissions.CreateBulk(allRolePermissions...).Save(ctx)
		if err != nil {
			return nil, err
		}
	}

	// 返回所有关联的权限（包括已存在的和新创建的）
	for _, perm := range req.Permissions {
		if perm.Id != 0 {
			if p, ok := permissionMap[perm.Id]; ok {
				result.Permissions = append(result.Permissions, p)
			}
		}
	}

	return result, nil
}

// DeleteRolePermission 删除角色下的权限关联
func (a *KnownAdminAPI) DeleteRolePermission(ctx context.Context, req *adminv1.DeleteRolePermissionRequest) (*emptypb.Empty, error) {
	if req.RoleId == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("role_id is required")
	}

	if req.PermissionId == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("permission_id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.RoleId)); err != nil {
		return nil, err
	}

	// 检查角色是否存在
	_, err = db.Roles.Get(ctx, int(req.RoleId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role not found")
	}

	// 检查权限是否存在
	_, err = db.Permissions.Get(ctx, int(req.PermissionId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("permission not found")
	}

	// 检查关联关系是否存在
	_, err = db.RolePermissions.Query().
		Where(
			rolepermissions.RoleIDEQ(int(req.RoleId)),
			rolepermissions.PermissionIDEQ(int(req.PermissionId)),
		).
		Only(ctx)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role permission relationship not found")
	}

	// 删除关联关系
	_, err = db.RolePermissions.Delete().
		Where(
			rolepermissions.RoleIDEQ(int(req.RoleId)),
			rolepermissions.PermissionIDEQ(int(req.PermissionId)),
		).
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// ListRolePermissions 列出角色下的所有权限
func (a *KnownAdminAPI) ListRolePermissions(ctx context.Context, req *adminv1.ListRolePermissionsRequest) (*adminv1.ListRolePermissionsResponse, error) {
	result := &adminv1.ListRolePermissionsResponse{}

	if req.RoleId == 0 {
		return result, errs.InvalidArgument(ctx).WithMessage("role_id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查用户是否有权限操作该角色
	if err := a.checkRolePermission(ctx, db, int(req.RoleId)); err != nil {
		return nil, err
	}

	// 检查角色是否存在
	_, err = db.Roles.Get(ctx, int(req.RoleId))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("role not found")
	}

	// 查询角色权限关联
	rolePermissionQuery := db.RolePermissions.Query().
		Where(rolepermissions.RoleIDEQ(int(req.RoleId)))

	// 如果 View 为 FULL，需要预加载权限的详细信息（策略和资源）
	if req.View == adminv1.View_VIEW_FULL {
		rolePermissionQuery = rolePermissionQuery.
			WithLionPermissions(
				func(query *lion.PermissionsQuery) {
					query.WithLionPolicies().
						WithLionPermissionBindings(
							func(query *lion.PermissionBindingsQuery) {
								query.WithLionResourceScopes(
									func(query *lion.ResourceScopesQuery) {
										query.WithLionResources().
											WithLionScopes()
									},
								)
							},
						)
				},
			)
	} else {
		// BASIC 或 STANDARD 视图，只加载基本信息
		rolePermissionQuery = rolePermissionQuery.WithLionPermissions()
	}

	// 计算总数（在应用分页前）
	totalSize, err := rolePermissionQuery.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	// 处理分页
	pageSize := GetPageSize(ctx, req.PageSize)

	// 处理排序
	if req.OrderBy != "" {
		switch req.OrderBy {
		case "create_time desc":
			rolePermissionQuery = rolePermissionQuery.Order(lion.Desc(rolepermissions.FieldCreatedAt))
		case "create_time asc":
			rolePermissionQuery = rolePermissionQuery.Order(lion.Asc(rolepermissions.FieldCreatedAt))
		default:
			rolePermissionQuery = rolePermissionQuery.Order(lion.Desc(rolepermissions.FieldCreatedAt))
		}
	} else {
		// 默认排序
		rolePermissionQuery = rolePermissionQuery.Order(lion.Desc(rolepermissions.FieldCreatedAt))
	}

	var lastID int
	if req.GetPageToken() != "" {
		// Cursor-based 分页
		data, err := base64.StdEncoding.DecodeString(req.GetPageToken())
		if err != nil {
			return nil, fmt.Errorf("invalid page_token: %w", err)
		}
		if err := json.Unmarshal(data, &lastID); err != nil {
			return nil, fmt.Errorf("invalid page_token format: %w", err)
		}
		if lastID > 0 {
			rolePermissionQuery = rolePermissionQuery.Where(rolepermissions.IDGT(lastID))
		}
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListRolePermissionsRequest_Offset:
		// Offset-based 分页
		rolePermissionQuery = rolePermissionQuery.Offset(int(p.Offset))
	case *adminv1.ListRolePermissionsRequest_PageToken:
		// Cursor-based 分页已在上面处理
	}

	// 应用 Limit
	rolePermissionQuery = rolePermissionQuery.Limit(int(pageSize))

	// 执行查询
	rolePermissionList, err := rolePermissionQuery.All(ctx)
	if err != nil {
		return nil, err
	}

	// 转换为响应格式
	for _, rp := range rolePermissionList {
		if rp.Edges.LionPermissions == nil {
			continue
		}

		perm := rp.Edges.LionPermissions
		permission := &adminv1.Permission{
			Id:          int64(perm.ID),
			Code:        perm.Code,
			DisplayName: perm.DisplayName,
			Description: perm.Description,
		}

		// 如果 View 为 FULL，加载策略和资源信息
		if req.View == adminv1.View_VIEW_FULL {
			// 加载策略信息
			if perm.Edges.LionPolicies != nil {
				policy := perm.Edges.LionPolicies
				permission.Policy = &adminv1.Policy{
					Id:          int64(policy.ID),
					Code:        policy.Code,
					DisplayName: policy.DisplayName,
					Type:        adminv1.Policy_Type(policy.PolicyType),
					Status:      adminv1.Policy_Status(policy.PolicyStatus),
					Value:       policy.Value,
					Description: policy.Description,
				}
			}

			// 加载权限绑定资源（permission_bindings -> resource_scopes -> resources），使用 Bindings 替代已废弃的 Resources
			if perm.Edges.LionPermissionBindings != nil {
				for _, binding := range perm.Edges.LionPermissionBindings {
					if pb := lionPermissionBindingToProto(binding); pb != nil {
						permission.Bindings = append(permission.Bindings, pb)
					}
				}
			}
		}

		result.Permissions = append(result.Permissions, permission)
	}

	// 构造 next_page_token（仅用于 cursor-based 分页）
	switch req.GetPagination().(type) {
	case *adminv1.ListRolePermissionsRequest_PageToken:
		// 只有在使用 cursor-based 分页时才生成 next_page_token
		if len(rolePermissionList) == int(pageSize) && len(rolePermissionList) > 0 {
			last := rolePermissionList[len(rolePermissionList)-1].ID
			tokenData, _ := json.Marshal(last)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}

	return result, nil
}

// 以下三个 RPC 及 enrichRoleDataRange 临时注释
//
// // CreateRoleDataRanges 为角色关联资源数据范围
// func (a *KnownAdminAPI) CreateRoleDataRanges(ctx context.Context, req *adminv1.CreateRoleDataRangesRequest) (*adminv1.CreateRoleDataRangesResponse, error) {
// 	result := &adminv1.CreateRoleDataRangesResponse{}
//
// 	if req.RoleId == 0 {
// 		return result, errs.InvalidArgument(ctx).WithMessage("role_id is required")
// 	}
//
// 	if len(req.DataRanges) == 0 {
// 		return result, errs.InvalidArgument(ctx).WithMessage("data_ranges list is empty")
// 	}
//
// 	db, err := a.GetLionClient()
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	// 检查用户是否有权限操作该角色
// 	if err := a.checkRolePermission(ctx, db, int(req.RoleId)); err != nil {
// 		return nil, err
// 	}
//
// 	// 获取创建者用户 ID
// 	userID, err := GetUserID(ctx)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	// 检查角色是否存在
// 	_, err = db.Roles.Get(ctx, int(req.RoleId))
// 	if err != nil {
// 		return nil, errs.NotFound(ctx).WithMessage("role not found")
// 	}
//
// 	// 验证并收集有效的数据范围
// 	validDataRanges := make([]*adminv1.RoleDataRange, 0, len(req.DataRanges))
// 	dataRangeKeys := make(map[string]bool) // 用于去重: "data_type:data_id"
//
// 	for _, dr := range req.DataRanges {
// 		// 验证 data_type
// 		if dr.DataType == adminv1.RoleDataRange_DATA_TYPE_UNSPECIFIED {
// 			continue
// 		}
//
// 		// 验证 data_id
// 		if dr.DataId == 0 {
// 			continue
// 		}
//
// 		// 根据 data_type 验证 data_id 是否存在
// 		dataTypeInt := int(dr.DataType)
// 		dataIDInt := int(dr.DataId)
//
// 		switch dr.DataType {
// 		case adminv1.RoleDataRange_DEPARTMENT:
// 			// 验证部门是否存在
// 			_, err := db.Departments.Get(ctx, dataIDInt)
// 			if err != nil {
// 				continue
// 			}
// 		case adminv1.RoleDataRange_RESOURCE:
// 			// 验证资源是否存在
// 			_, err := db.Resources.Get(ctx, dataIDInt)
// 			if err != nil {
// 				continue
// 			}
// 		default:
// 			continue
// 		}
//
// 		// 检查是否已存在相同的关联关系
// 		key := fmt.Sprintf("%d:%d", dataTypeInt, dataIDInt)
// 		if dataRangeKeys[key] {
// 			continue
// 		}
//
// 		// 检查数据库中是否已存在
// 		existing, err := db.RoleDataRanges.Query().
// 			Where(
// 				roledataranges.RoleIDEQ(int(req.RoleId)),
// 				roledataranges.DataTypeEQ(dataTypeInt),
// 				roledataranges.DataIDEQ(dataIDInt),
// 			).
// 			Only(ctx)
// 		if err == nil && existing != nil {
// 			// 已存在，跳过
// 			continue
// 		}
//
// 		dataRangeKeys[key] = true
// 		validDataRanges = append(validDataRanges, dr)
// 	}
//
// 	if len(validDataRanges) == 0 {
// 		return result, errs.InvalidArgument(ctx).WithMessage("no valid data ranges found")
// 	}
//
// 	// 批量创建关联关系
// 	allRoleDataRanges := make([]*lion.RoleDataRangesCreate, 0, len(validDataRanges))
// 	for _, dr := range validDataRanges {
// 		rd := db.RoleDataRanges.Create().
// 			SetRoleID(int(req.RoleId)).
// 			SetDataType(int(dr.DataType)).
// 			SetDataID(int(dr.DataId)).
// 			SetIsRecursive(dr.IsRecursive).
// 			SetCreatedBy(userID).
// 			SetUpdatedBy(userID)
//
// 		allRoleDataRanges = append(allRoleDataRanges, rd)
// 	}
//
// 	createdRanges, err := db.RoleDataRanges.CreateBulk(allRoleDataRanges...).Save(ctx)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	// 转换为响应格式
// 	for _, rd := range createdRanges {
// 		dataRange := &adminv1.RoleDataRange{
// 			Id:          int64(rd.ID),
// 			RoleId:      int64(rd.RoleID),
// 			DataType:    adminv1.RoleDataRange_DataType(rd.DataType),
// 			DataId:      int64(rd.DataID),
// 			IsRecursive: rd.IsRecursive,
// 			CreatedAt:   timestamppb.New(rd.CreatedAt),
// 			UpdatedAt:   timestamppb.New(rd.UpdatedAt),
// 			CreatedBy:   rd.CreatedBy,
// 			UpdatedBy:   rd.UpdatedBy,
// 		}
//
// 		// 根据 data_type 和 data_id 从对应表补充 code/display_name/description
// 		a.enrichRoleDataRange(ctx, db, rd, dataRange)
//
// 		result.DataRanges = append(result.DataRanges, dataRange)
// 	}
//
// 	return result, nil
// }
//
// // DeleteRoleDataRanges 删除角色下关联资源数据范围
// func (a *KnownAdminAPI) DeleteRoleDataRanges(ctx context.Context, req *adminv1.DeleteRoleDataRangesRequest) (*emptypb.Empty, error) {
// 	if req.RoleId == 0 {
// 		return nil, errs.InvalidArgument(ctx).WithMessage("role_id is required")
// 	}
//
// 	if req.DataRangeId == 0 {
// 		return nil, errs.InvalidArgument(ctx).WithMessage("data_range_id is required")
// 	}
//
// 	db, err := a.GetLionClient()
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	// 检查用户是否有权限操作该角色
// 	if err := a.checkRolePermission(ctx, db, int(req.RoleId)); err != nil {
// 		return nil, err
// 	}
//
// 	// 检查角色是否存在
// 	_, err = db.Roles.Get(ctx, int(req.RoleId))
// 	if err != nil {
// 		return nil, errs.NotFound(ctx).WithMessage("role not found")
// 	}
//
// 	// 检查数据范围是否存在且属于该角色
// 	dataRange, err := db.RoleDataRanges.Query().
// 		Where(
// 			roledataranges.ID(int(req.DataRangeId)),
// 			roledataranges.RoleIDEQ(int(req.RoleId)),
// 		).
// 		Only(ctx)
// 	if err != nil {
// 		return nil, errs.NotFound(ctx).WithMessage("role data range not found")
// 	}
//
// 	// 删除关联关系
// 	err = db.RoleDataRanges.DeleteOne(dataRange).Exec(ctx)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	return &emptypb.Empty{}, nil
// }
//
// // ListRoleDataRanges 列出角色下关联资源数据范围
// func (a *KnownAdminAPI) ListRoleDataRanges(ctx context.Context, req *adminv1.ListRoleDataRangesRequest) (*adminv1.ListRoleDataRangesResponse, error) {
// 	result := &adminv1.ListRoleDataRangesResponse{}
//
// 	if req.RoleId == 0 {
// 		return result, errs.InvalidArgument(ctx).WithMessage("role_id is required")
// 	}
//
// 	db, err := a.GetLionClient()
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	// 检查用户是否有权限操作该角色
// 	if err := a.checkRolePermission(ctx, db, int(req.RoleId)); err != nil {
// 		return nil, err
// 	}
//
// 	// 检查角色是否存在
// 	_, err = db.Roles.Get(ctx, int(req.RoleId))
// 	if err != nil {
// 		return nil, errs.NotFound(ctx).WithMessage("role not found")
// 	}
//
// 	// 查询角色数据范围关联
// 	query := db.RoleDataRanges.Query().
// 		Where(roledataranges.RoleIDEQ(int(req.RoleId)))
//
// 	// 处理过滤条件（filter）
// 	// TODO: 实现完整的 AIP-160 filter 语法解析
// 	// 这里先支持简单的 data_type 过滤
// 	if req.Filter != "" {
// 		// 简单实现：支持 data_type=1 格式
// 		// 实际应该使用完整的 filter 解析器
// 		if strings.HasPrefix(req.Filter, "data_type=") {
// 			dataTypeStr := strings.TrimPrefix(req.Filter, "data_type=")
// 			if dataType, err := strconv.Atoi(dataTypeStr); err == nil {
// 				query = query.Where(roledataranges.DataTypeEQ(dataType))
// 			}
// 		}
// 	}
//
// 	// 计算总数（在应用分页前）
// 	totalSize, err := query.Clone().Count(ctx)
// 	if err != nil {
// 		return nil, err
// 	}
// 	result.TotalSize = int32(totalSize)
//
// 	// 处理分页
// 	pageSize := GetPageSize(ctx, req.PageSize)
//
// 	// 处理排序
// 	if req.OrderBy != "" {
// 		// 支持多种排序字段
// 		orderParts := strings.Split(req.OrderBy, ",")
// 		for _, part := range orderParts {
// 			part = strings.TrimSpace(part)
// 			if strings.HasPrefix(part, "created_at desc") || strings.HasPrefix(part, "create_time desc") {
// 				query = query.Order(lion.Desc(roledataranges.FieldCreatedAt))
// 			} else if strings.HasPrefix(part, "created_at asc") || strings.HasPrefix(part, "create_time asc") {
// 				query = query.Order(lion.Asc(roledataranges.FieldCreatedAt))
// 			} else if strings.HasPrefix(part, "data_type desc") {
// 				query = query.Order(lion.Desc(roledataranges.FieldDataType))
// 			} else if strings.HasPrefix(part, "data_type asc") {
// 				query = query.Order(lion.Asc(roledataranges.FieldDataType))
// 			}
// 		}
// 	} else {
// 		// 默认排序：按创建时间倒序
// 		query = query.Order(lion.Desc(roledataranges.FieldCreatedAt))
// 	}
//
// 	var lastID int
// 	if req.GetPageToken() != "" {
// 		// Cursor-based 分页
// 		data, err := base64.StdEncoding.DecodeString(req.GetPageToken())
// 		if err != nil {
// 			return nil, fmt.Errorf("invalid page_token: %w", err)
// 		}
// 		if err := json.Unmarshal(data, &lastID); err != nil {
// 			return nil, fmt.Errorf("invalid page_token format: %w", err)
// 		}
// 		if lastID > 0 {
// 			query = query.Where(roledataranges.IDGT(lastID))
// 		}
// 	}
//
// 	switch p := req.GetPagination().(type) {
// 	case *adminv1.ListRoleDataRangesRequest_Offset:
// 		// Offset-based 分页
// 		query = query.Offset(int(p.Offset))
// 	case *adminv1.ListRoleDataRangesRequest_PageToken:
// 		// Cursor-based 分页已在上面处理
// 	}
//
// 	// 应用 Limit
// 	query = query.Limit(int(pageSize))
//
// 	// 执行查询
// 	roleDataRangeList, err := query.All(ctx)
// 	if err != nil {
// 		return nil, err
// 	}
//
// 	// 转换为响应格式
// 	for _, rd := range roleDataRangeList {
// 		dataRange := &adminv1.RoleDataRange{
// 			Id:          int64(rd.ID),
// 			RoleId:      int64(rd.RoleID),
// 			DataType:    adminv1.RoleDataRange_DataType(rd.DataType),
// 			DataId:      int64(rd.DataID),
// 			IsRecursive: rd.IsRecursive,
// 		}
//
// 		// 根据 data_type 和 data_id 从对应表补充 code/display_name/description
// 		a.enrichRoleDataRange(ctx, db, rd, dataRange)
//
// 		// 如果 View 为 FULL，添加更多详细信息
// 		if req.View == adminv1.View_VIEW_FULL {
// 			dataRange.CreatedAt = timestamppb.New(rd.CreatedAt)
// 			dataRange.UpdatedAt = timestamppb.New(rd.UpdatedAt)
// 			dataRange.CreatedBy = rd.CreatedBy
// 			dataRange.UpdatedBy = rd.UpdatedBy
// 		}
//
// 		result.DataRanges = append(result.DataRanges, dataRange)
// 	}
//
// 	// 构造 next_page_token（仅用于 cursor-based 分页）
// 	switch req.GetPagination().(type) {
// 	case *adminv1.ListRoleDataRangesRequest_PageToken:
// 		// 只有在使用 cursor-based 分页时才生成 next_page_token
// 		if len(roleDataRangeList) == int(pageSize) && len(roleDataRangeList) > 0 {
// 			last := roleDataRangeList[len(roleDataRangeList)-1].ID
// 			tokenData, _ := json.Marshal(last)
// 			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
// 		}
// 	}
//
// 	return result, nil
// }
//
// // enrichRoleDataRange 根据 data_type 从对应表补全 RoleDataRange 的展示字段
// // - 当 data_type=RESOURCE 时，从 lion_resources 表获取 code/display_name/description
// // - 当 data_type=DEPARTMENT 时，从 lion_departments 表获取 code/display_name/description
// func (a *KnownAdminAPI) enrichRoleDataRange(ctx context.Context, db *lion.Client, rd *lion.RoleDataRanges, dataRange *adminv1.RoleDataRange) {
// 	switch adminv1.RoleDataRange_DataType(rd.DataType) {
// 	case adminv1.RoleDataRange_RESOURCE:
// 		res, err := db.Resources.Get(ctx, rd.DataID)
// 		if err != nil {
// 			return
// 		}
// 		dataRange.Code = res.Code
// 		dataRange.DisplayName = res.DisplayName
// 		if res.Description != "" {
// 			dataRange.Description = res.Description
// 		}
// 	case adminv1.RoleDataRange_DEPARTMENT:
// 		dep, err := db.Departments.Get(ctx, rd.DataID)
// 		if err != nil {
// 			return
// 		}
// 		dataRange.Code = dep.Code
// 		dataRange.DisplayName = dep.DisplayName
// 		if dep.Description != "" {
// 			dataRange.Description = dep.Description
// 		}
// 	default:
// 		// 其他类型暂不处理
// 	}
// }
