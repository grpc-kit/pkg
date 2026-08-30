package admin

import (
	"context"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/usermemberships"
	"github.com/grpc-kit/pkg/lion/users"
)

// groupMatchesUser resolves one group without enumerating its members. The
// batched token-claim path uses the same rule AST and equivalent source
// predicates in effectiveGroupCodesForUserAt.
func groupMatchesUser(ctx context.Context, db *lion.Client, group *lion.Groups, userID int, now time.Time) (bool, error) {
	if group == nil || userID <= 0 {
		return false, errs.InvalidArgument(ctx).WithMessage("group and user_id are required")
	}
	if _, err := groupToProto(group, false); err != nil {
		return false, errs.FailedPrecondition(ctx).WithMessage(err.Error())
	}
	switch adminv1.Group_Type(group.GroupType) {
	case adminv1.Group_PROJECT, adminv1.Group_EXTERNAL, adminv1.Group_COMMUNITY:
		return db.UserMemberships.Query().Where(
			usermemberships.UserIDEQ(userID),
			usermemberships.TargetTypeEQ(membershipTargetGroup),
			usermemberships.TargetIDEQ(group.ID),
			usermemberships.MemberStatusEQ(int(adminv1.Membership_ACTIVE)),
			usermemberships.Or(usermemberships.ExpiresAtIsNil(), usermemberships.ExpiresAtGT(now)),
		).Exist(ctx)
	case adminv1.Group_DEPARTMENT:
		valid, err := db.Departments.Query().Where(
			departments.IDEQ(*group.SourceID),
			departments.DepartmentStatusEQ(int(adminv1.Department_ACTIVE)),
			departments.DeletedAtIsNil(),
		).Exist(ctx)
		if err != nil || !valid {
			return false, err
		}
		return db.UserMemberships.Query().Where(
			usermemberships.UserIDEQ(userID),
			usermemberships.TargetTypeEQ(membershipTargetDepartment),
			usermemberships.TargetIDEQ(*group.SourceID),
			usermemberships.MemberStatusEQ(int(adminv1.Membership_ACTIVE)),
			usermemberships.Or(usermemberships.ExpiresAtIsNil(), usermemberships.ExpiresAtGT(now)),
		).Exist(ctx)
	case adminv1.Group_ROLE:
		valid, err := db.Roles.Query().Where(
			roles.IDEQ(*group.SourceID),
			roles.RoleStatusEQ(int(adminv1.Role_ACTIVE)),
			roles.DeletedAtIsNil(),
		).Exist(ctx)
		if err != nil || !valid {
			return false, err
		}
		roleIDs, err := effectiveRoleIDsForUserAt(ctx, db, userID, now)
		if err != nil {
			return false, err
		}
		return containsInt(roleIDs, *group.SourceID), nil
	case adminv1.Group_DYNAMIC, adminv1.Group_SYSTEM:
		compiled, err := decodeStoredUserFilter(group.Config)
		if err != nil {
			return false, errs.FailedPrecondition(ctx).WithMessage("group rule config is invalid")
		}
		user, err := db.Users.Query().Select(
			users.FieldID,
			users.FieldUserType,
			users.FieldUserStatus,
			users.FieldEmailVerified,
			users.FieldPhoneNumberVerified,
			users.FieldDeletedAt,
		).Where(users.IDEQ(userID), users.DeletedAtIsNil()).Only(ctx)
		if err != nil {
			return false, err
		}
		return compiled.matches(user), nil
	default:
		return false, errs.FailedPrecondition(ctx).WithMessage("unsupported group type")
	}
}
