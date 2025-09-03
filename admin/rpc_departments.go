package admin

import (
	"context"
	"strconv"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/departmentleaders"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/rpc"
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

	result = &adminv1.Department{
		Id:          int32(dp.ID),
		Name:        dp.Name,
		I18NName:    I18NNameParse(dp.I18nName),
		OrderWeight: int32(dp.OrderWeight),
		Leaders:     make([]*adminv1.Department_Leader, 0),
	}

	if req.Department.Leaders != nil {
		for _, leader := range req.Department.Leaders {
			tmp, err := tx.DepartmentLeaders.Create().
				SetDepartmentID(dp.ID).
				SetLeaderType(int(leader.Type)).
				SetUserID(int(leader.UserId)).
				Save(ctx)
			if err != nil {
				_ = tx.Rollback()
				return result, err
			}

			result.Leaders = append(result.Leaders, &adminv1.Department_Leader{
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

	userIDStr, ok := rpc.GetUserIDFromContext(ctx)
	if !ok {
		return result, errs.Unauthenticated(ctx).WithMessage("user id not found")
	}

	userIDInt, err := strconv.Atoi(userIDStr)
	if err != nil {
		return result, err
	}

	leaders, err := a.config.db.DepartmentLeaders.Query().
		Where(departmentleaders.UserIDEQ(userIDInt)).
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

	result.Departments = deps

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
		_, err = a.config.db.Departments.Delete().
			Where(
				departments.ID(int(req.Id)),
			).Exec(ctx)

		return empty, err
	}

	return empty, errs.PermissionDenied(ctx)
}

func (a *KnownAdminAPI) buildDepartmentTree(ctx context.Context, dep *lion.Departments) (*adminv1.Department, error) {
	// 查子部门
	children, err := a.config.db.Departments.
		Query().
		Where(departments.ParentIDEQ(dep.ID)).All(ctx)
	if err != nil {
		return nil, err
	}

	// 查领导
	leaders, err := a.config.db.DepartmentLeaders.Query().
		Where(departmentleaders.HasLionDepartmentsWith(departments.ID(dep.ID))).All(ctx)

	pbDep := &adminv1.Department{
		Id:          int32(dep.ID),
		ParentId:    int32(dep.ParentID),
		Name:        dep.Name,
		I18NName:    I18NNameParse(dep.I18nName),
		OrderWeight: int32(dep.OrderWeight),
		Leaders:     make([]*adminv1.Department_Leader, 0),
	}

	for _, l := range leaders {
		pbDep.Leaders = append(pbDep.Leaders, &adminv1.Department_Leader{
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
