package admin

import (
	"context"
	"sort"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/roledepartments"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/userdepartments"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/protobuf/types/known/emptypb"
)

// CreateDepartment 创建部门
func (a *KnownAdminAPI) CreateDepartment(ctx context.Context, req *adminv1.CreateDepartmentRequest) (*adminv1.Department, error) {
	result := &adminv1.Department{}

	if req == nil || req.Department == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body department is nil")
	}

	tx, err := a.config.db.Tx(ctx)
	if err != nil {
		return result, err
	}

	// 确认父部门存在
	if req.Department.ParentId != 0 {
		_, err = tx.Departments.Get(ctx, int(req.Department.ParentId))
		if err != nil {
			_ = tx.Rollback()
			return result, errs.InvalidArgument(ctx).WithMessage("department parent id not found")
		}
	}

	// 创建部门
	dp, err := tx.Departments.Create().
		SetParentID(int(req.Department.ParentId)).
		SetName(req.Department.Name).
		SetI18nName(I18NNameJSON(req.Department.I18NName)).
		SetOrderWeight(int(req.Department.OrderWeight)).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return result, err
	}

	// 自动插入对超级管理员插入权限
	ros, err := tx.Roles.Query().Select(roles.FieldID).Where(roles.NameEQ("superadmin")).Only(ctx)
	if err != nil {
		_ = tx.Rollback()
		return result, err
	}
	_, err = tx.RoleDepartments.Create().SetRoleID(ros.ID).SetDepartmentID(dp.ID).Save(ctx)

	result = &adminv1.Department{
		Id:          int32(dp.ID),
		Name:        dp.Name,
		I18NName:    I18NNameParse(dp.I18nName),
		OrderWeight: int32(dp.OrderWeight),
		Leaders:     make([]*adminv1.Leader, 0),
	}

	if req.Department.Leaders != nil {
		for _, leader := range req.Department.Leaders {
			tmp, err := tx.UserDepartments.Create().
				SetDepartmentID(dp.ID).
				SetLeaderType(int(leader.Type)).
				SetUserID(int(leader.UserId)).
				Save(ctx)
			if err != nil {
				_ = tx.Rollback()
				return result, err
			}

			result.Leaders = append(result.Leaders, &adminv1.Leader{
				Type:   int32(tmp.LeaderType),
				UserId: int32(tmp.UserID),
			})
		}
	}

	_ = tx.Commit()

	return result, nil
}

// ListDepartments 列出部门
func (a *KnownAdminAPI) ListDepartments(ctx context.Context, req *adminv1.ListDepartmentsRequest) (*adminv1.ListDepartmentsResponse, error) {
	result := &adminv1.ListDepartmentsResponse{}

	rids, err := a.getUserRoleID(ctx)
	if err != nil {
		return result, err
	}

	res, err := a.config.db.RoleDepartments.Query().Select(
		roledepartments.FieldRoleID,
		roledepartments.FieldDepartmentID,
	).Where(
		roledepartments.RoleIDIn(rids...),
	).All(ctx)
	if err != nil {
		return result, err
	}

	depIDs := make([]int, 0)
	for _, v := range res {
		depIDs = append(depIDs, v.DepartmentID)
	}

	depObj, err := a.config.db.Departments.Query().
		Select().
		Where(
			departments.IDIn(depIDs...),
		).All(ctx)
	if err != nil {
		return result, err
	}

	// 构建树状菜单
	menuMap := make(map[int32]*adminv1.Department)
	var roots []*adminv1.Department

	for _, m := range depObj {
		menu := &adminv1.Department{
			Id:          int32(m.ID),
			ParentId:    int32(m.ParentID),
			Name:        m.Name,
			I18NName:    I18NNameParse(m.I18nName),
			OrderWeight: int32(m.OrderWeight),
		}
		menuMap[int32(m.ID)] = menu
	}

	for _, menu := range menuMap {
		/*
			if menu.ParentId == 0 {
				roots = append(roots, menu)
				continue
			}
		*/

		if parent, ok := menuMap[menu.ParentId]; ok {
			parent.Children = append(parent.Children, menu)
		}
	}

	// TODO；如果不存在 "parent_id=0" 的情况，动态找出最上层节点
	hasParent := make(map[int32]bool)
	for _, menu := range menuMap {
		if _, ok := menuMap[menu.ParentId]; ok {
			hasParent[menu.Id] = true
		}
	}
	for _, menu := range menuMap {
		if !hasParent[menu.Id] { // 没有父节点
			roots = append(roots, menu)
		}
	}

	// 可选：对根菜单排序
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].OrderWeight < roots[j].OrderWeight
	})

	result.Departments = roots

	/*
		leaders, err := a.config.db.UserDepartments.Query().
			Where(userdepartments.UserIDEQ(userIDInt)).
			WithLionDepartments().All(ctx)
		if err != nil {
			return result, err
		}

		var deps []*adminv1.Department
		for _, l := range leaders {
			dep := l.Edges.LionDepartments
			if dep == nil {
				continue
			}

			tree, err := a.buildDepartmentTree(ctx, dep)
			if err != nil {
				return result, err
			}

			deps = append(deps, tree)
		}
	*/

	// result.Departments = deps

	return result, nil
}

// DeleteDepartment 删除部门
func (a *KnownAdminAPI) DeleteDepartment(ctx context.Context, req *adminv1.DeleteDepartmentRequest) (*emptypb.Empty, error) {
	empty := &emptypb.Empty{}

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
		count := a.config.db.Users.Query().Where(users.DepartmentIDEQ(int(req.Id))).CountX(ctx)
		if count > 0 {
			return empty, errs.PermissionDenied(ctx).WithMessage("department has users")
		}

		_, err = a.config.db.Departments.Delete().
			Where(
				departments.ID(int(req.Id)),
			).Exec(ctx)

		return empty, err
	}

	return empty, errs.PermissionDenied(ctx)
}

// UpdateDepartment 更新部门
func (a *KnownAdminAPI) UpdateDepartment(ctx context.Context, req *adminv1.UpdateDepartmentRequest) (*adminv1.Department, error) {
	result := &adminv1.Department{}

	if req == nil || req.Department == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body department is nil")
	}

	if req.UpdateMask != nil && len(req.UpdateMask.Paths) != 0 {
		x := a.config.db.Departments.Update()

		for _, path := range req.UpdateMask.Paths {
			switch path {
			case "name":
				x.SetName(req.Department.Name)
			case "i18n_name.en_us":
			// TODO;
			case "order_weight":
				x.SetOrderWeight(int(req.Department.OrderWeight))
			}
		}

		_, err := x.Where(departments.IDEQ(int(req.Department.Id))).Save(ctx)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
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

	// 查领导
	leaders, err := a.config.db.UserDepartments.Query().
		Where(userdepartments.HasLionDepartmentsWith(departments.ID(dep.ID))).All(ctx)

	pbDep := &adminv1.Department{
		Id:          int32(dep.ID),
		ParentId:    int32(dep.ParentID),
		Name:        dep.Name,
		I18NName:    I18NNameParse(dep.I18nName),
		OrderWeight: int32(dep.OrderWeight),
		Leaders:     make([]*adminv1.Leader, 0),
	}

	for _, l := range leaders {
		pbDep.Leaders = append(pbDep.Leaders, &adminv1.Leader{
			Type:   int32(l.LeaderType),
			UserId: int32(l.UserID),
		})
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
