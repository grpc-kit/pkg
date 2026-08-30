package admin

import (
	"context"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/groups"
	"github.com/grpc-kit/pkg/lion/principalroles"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/usermemberships"
	"github.com/grpc-kit/pkg/lion/users"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// DeleteDepartment moves a leaf department to the recycle bin. Authorization
// is enforced by IAM/OPA before this handler is called.
func (a *KnownAdminAPI) DeleteDepartment(ctx context.Context, req *adminv1.DeleteDepartmentRequest) (*adminv1.Department, error) {
	if req == nil || req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("id is invalid")
	}
	actorID, err := GetUserID(ctx)
	if err != nil || actorID <= 0 {
		return nil, errs.PermissionDenied(ctx).WithMessage("authenticated user id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database unavailable")
	}
	if err := a.checkDepartmentPermission(ctx, db, int(req.GetId())); err != nil {
		return nil, err
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("begin delete department transaction failed")
	}
	defer func() { _ = tx.Rollback() }()

	targetID := int(req.GetId())
	department, err := tx.Departments.Query().Where(
		departments.IDEQ(targetID),
		departments.DeletedAtIsNil(),
	).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("department not found")
		}
		return nil, errs.Internal(ctx).WithMessage("query department failed")
	}
	if err := ensureDepartmentDeleteAllowed(ctx, tx, department); err != nil {
		return nil, err
	}

	affected, err := tx.Departments.Update().Where(
		departments.IDEQ(targetID),
		departments.DeletedAtIsNil(),
	).SetDeletedAt(time.Now()).
		SetDepartmentStatus(int(adminv1.Department_INACTIVE)).
		SetUpdatedBy(actorID).
		Save(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("soft delete department failed")
	}
	if affected != 1 {
		return nil, errs.NotFound(ctx).WithMessage("department not found")
	}
	if err := a.ensureDepartmentDeleteLeavesSuperadmin(ctx, tx, targetID); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, errs.Internal(ctx).WithMessage("commit delete department failed")
	}

	row, err := db.Departments.Query().Where(departments.IDEQ(targetID)).Only(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("read deleted department failed")
	}
	return departmentToProto(row), nil
}

// UndeleteDepartment restores a department in INACTIVE state. An explicit
// UpdateDepartment call is required before it can become effective again.
func (a *KnownAdminAPI) UndeleteDepartment(ctx context.Context, req *adminv1.UndeleteDepartmentRequest) (*adminv1.Department, error) {
	if req == nil || req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("id is invalid")
	}
	actorID, err := GetUserID(ctx)
	if err != nil || actorID <= 0 {
		return nil, errs.PermissionDenied(ctx).WithMessage("authenticated user id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database unavailable")
	}
	if err := a.checkDepartmentPermission(ctx, db, int(req.GetId())); err != nil {
		return nil, err
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("begin undelete department transaction failed")
	}
	defer func() { _ = tx.Rollback() }()

	targetID := int(req.GetId())
	department, err := tx.Departments.Query().Where(
		departments.IDEQ(targetID),
		departments.DeletedAtNotNil(),
	).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			exists, existsErr := tx.Departments.Query().Where(departments.IDEQ(targetID)).Exist(ctx)
			if existsErr != nil {
				return nil, errs.Internal(ctx).WithMessage("query department failed")
			}
			if exists {
				return nil, errs.AlreadyExists(ctx).WithMessage("department is not deleted")
			}
			return nil, errs.NotFound(ctx).WithMessage("department not found")
		}
		return nil, errs.Internal(ctx).WithMessage("query department failed")
	}
	if department.ParentID != 0 {
		parentExists, err := tx.Departments.Query().Where(
			departments.IDEQ(department.ParentID),
			departments.DeletedAtIsNil(),
		).Exist(ctx)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage("query department parent failed")
		}
		if !parentExists {
			return nil, errs.FailedPrecondition(ctx).WithMessage("department parent must be restored before undelete")
		}
	}

	affected, err := tx.Departments.Update().Where(
		departments.IDEQ(targetID),
		departments.DeletedAtNotNil(),
	).ClearDeletedAt().
		SetDepartmentStatus(int(adminv1.Department_INACTIVE)).
		SetUpdatedBy(actorID).
		Save(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("undelete department failed")
	}
	if affected != 1 {
		return nil, errs.NotFound(ctx).WithMessage("department not found")
	}
	if err := tx.Commit(); err != nil {
		return nil, errs.Internal(ctx).WithMessage("commit undelete department failed")
	}

	row, err := db.Departments.Query().Where(departments.IDEQ(targetID)).Only(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("read restored department failed")
	}
	return departmentToProto(row), nil
}

// ExpungeDepartment permanently removes a soft-deleted department and its core
// polymorphic bindings. Department groups are intentionally a blocking weak
// reference so an undelete never points at an already-purged department.
func (a *KnownAdminAPI) ExpungeDepartment(ctx context.Context, req *adminv1.ExpungeDepartmentRequest) (*emptypb.Empty, error) {
	if req == nil || req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("id is invalid")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database unavailable")
	}
	if err := a.checkDepartmentPermission(ctx, db, int(req.GetId())); err != nil {
		return nil, err
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("begin expunge department transaction failed")
	}
	defer func() { _ = tx.Rollback() }()

	targetID := int(req.GetId())
	department, err := tx.Departments.Query().Where(
		departments.IDEQ(targetID),
		departments.DeletedAtNotNil(),
	).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			exists, existsErr := tx.Departments.Query().Where(departments.IDEQ(targetID)).Exist(ctx)
			if existsErr != nil {
				return nil, errs.Internal(ctx).WithMessage("query department failed")
			}
			if exists {
				return nil, errs.FailedPrecondition(ctx).WithMessage("department must be soft-deleted before expunge")
			}
			return nil, errs.NotFound(ctx).WithMessage("department not found")
		}
		return nil, errs.Internal(ctx).WithMessage("query department failed")
	}
	if err := ensureDepartmentExpungeAllowed(ctx, tx, department); err != nil {
		return nil, err
	}

	for _, cleanup := range []func() error{
		func() error {
			_, err := tx.UserMemberships.Delete().Where(
				usermemberships.TargetTypeEQ(membershipTargetDepartment),
				usermemberships.TargetIDEQ(targetID),
			).Exec(ctx)
			return err
		},
		func() error {
			_, err := tx.PrincipalRoles.Delete().Where(
				principalroles.PrincipalTypeEQ(principalTypeDepartment),
				principalroles.PrincipalIDEQ(targetID),
			).Exec(ctx)
			return err
		},
	} {
		if err := cleanup(); err != nil {
			return nil, errs.Internal(ctx).WithMessage("clean department dependent data failed")
		}
	}
	affected, err := tx.Departments.Delete().Where(
		departments.IDEQ(targetID),
		departments.DeletedAtNotNil(),
	).Exec(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("expunge department failed")
	}
	if affected != 1 {
		return nil, errs.NotFound(ctx).WithMessage("department not found")
	}
	if err := tx.Commit(); err != nil {
		return nil, errs.Internal(ctx).WithMessage("commit expunge department failed")
	}
	return &emptypb.Empty{}, nil
}

func ensureDepartmentDeleteAllowed(ctx context.Context, tx *lion.Tx, department *lion.Departments) error {
	if department.Protected || isBuiltinDepartmentCode(department.Code) {
		return errs.FailedPrecondition(ctx).WithMessage("protected department cannot be deleted")
	}
	hasChildren, err := tx.Departments.Query().Where(departments.ParentIDEQ(department.ID)).Exist(ctx)
	if err != nil {
		return errs.Internal(ctx).WithMessage("query department children failed")
	}
	if hasChildren {
		return errs.FailedPrecondition(ctx).WithMessage("department with children cannot be deleted")
	}
	hasGroups, err := tx.Groups.Query().Where(
		groups.GroupTypeEQ(int(adminv1.Group_DEPARTMENT)),
		groups.SourceIDEQ(department.ID),
	).Exist(ctx)
	if err != nil {
		return errs.Internal(ctx).WithMessage("query department group references failed")
	}
	if hasGroups {
		return errs.FailedPrecondition(ctx).WithMessage("department referenced by group cannot be deleted")
	}
	return nil
}

func ensureDepartmentExpungeAllowed(ctx context.Context, tx *lion.Tx, department *lion.Departments) error {
	if department.Protected || isBuiltinDepartmentCode(department.Code) {
		return errs.FailedPrecondition(ctx).WithMessage("protected department cannot be expunged")
	}
	hasChildren, err := tx.Departments.Query().Where(departments.ParentIDEQ(department.ID)).Exist(ctx)
	if err != nil {
		return errs.Internal(ctx).WithMessage("query department children failed")
	}
	if hasChildren {
		return errs.FailedPrecondition(ctx).WithMessage("department with children cannot be expunged")
	}
	hasGroups, err := tx.Groups.Query().Where(
		groups.GroupTypeEQ(int(adminv1.Group_DEPARTMENT)),
		groups.SourceIDEQ(department.ID),
	).Exist(ctx)
	if err != nil {
		return errs.Internal(ctx).WithMessage("query department group references failed")
	}
	if hasGroups {
		return errs.FailedPrecondition(ctx).WithMessage("department referenced by group cannot be expunged")
	}
	return nil
}

func (a *KnownAdminAPI) ensureDepartmentDeleteLeavesSuperadmin(ctx context.Context, tx *lion.Tx, departmentID int) error {
	superadmin, err := tx.Roles.Query().Where(roles.CodeEQ(seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN))).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil
		}
		return errs.Internal(ctx).WithMessage("query superadmin role failed")
	}
	if _, err := tx.Roles.Update().Where(roles.IDEQ(superadmin.ID)).SetUpdatedAt(superadmin.UpdatedAt).Save(ctx); err != nil {
		return errs.Internal(ctx).WithMessage("lock superadmin role failed")
	}

	now := time.Now()
	hasBinding, err := tx.PrincipalRoles.Query().Where(
		principalroles.PrincipalTypeEQ(principalTypeDepartment),
		principalroles.PrincipalIDEQ(departmentID),
		principalroles.RoleIDEQ(superadmin.ID),
		principalroles.BindingStatusEQ(bindingStatusActive),
		principalroles.Or(principalroles.ExpiresAtIsNil(), principalroles.ExpiresAtGT(now)),
	).Exist(ctx)
	if err != nil {
		return errs.Internal(ctx).WithMessage("query department superadmin binding failed")
	}
	if !hasBinding {
		return nil
	}
	hasMember, err := tx.UserMemberships.Query().Where(
		usermemberships.TargetTypeEQ(membershipTargetDepartment),
		usermemberships.TargetIDEQ(departmentID),
		usermemberships.MemberStatusEQ(int(adminv1.Membership_ACTIVE)),
		usermemberships.Or(usermemberships.ExpiresAtIsNil(), usermemberships.ExpiresAtGT(now)),
	).Exist(ctx)
	if err != nil {
		return errs.Internal(ctx).WithMessage("query department members failed")
	}
	if !hasMember {
		return nil
	}

	candidates, err := tx.Users.Query().Select(users.FieldID).Where(
		users.UserStatusEQ(int(adminv1.User_ACTIVE)),
		users.DeletedAtIsNil(),
	).All(ctx)
	if err != nil {
		return errs.Internal(ctx).WithMessage("query active users failed")
	}
	for _, candidate := range candidates {
		roleIDs, err := effectiveRoleIDsForUserAt(ctx, tx.Client(), candidate.ID, now)
		if err != nil {
			return errs.Internal(ctx).WithMessage("resolve active user roles failed")
		}
		if containsInt(roleIDs, superadmin.ID) {
			return nil
		}
	}
	return errs.FailedPrecondition(ctx).WithMessage("cannot delete department that removes the last active superadmin")
}
