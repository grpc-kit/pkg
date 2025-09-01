package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
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
		_, err := tx.Departments.Get(ctx, int(req.Department.ParentId))
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
