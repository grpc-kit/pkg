package admin

import (
	"context"
	"fmt"
	"time"

	"entgo.io/ent/dialect/sql"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/groups"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/principalroles"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/usermemberships"
	"github.com/grpc-kit/pkg/lion/users"
)

func activeMembershipSQL(table *sql.SelectTable, now time.Time) *sql.Predicate {
	return sql.And(
		sql.EQ(table.C(usermemberships.FieldMemberStatus), int(adminv1.Membership_ACTIVE)),
		sql.Or(
			sql.IsNull(table.C(usermemberships.FieldExpiresAt)),
			sql.GT(table.C(usermemberships.FieldExpiresAt), now),
		),
	)
}

func activePrincipalRoleSQL(table *sql.SelectTable, now time.Time) *sql.Predicate {
	return sql.And(
		sql.EQ(table.C(principalroles.FieldBindingStatus), bindingStatusActive),
		sql.Or(
			sql.IsNull(table.C(principalroles.FieldExpiresAt)),
			sql.GT(table.C(principalroles.FieldExpiresAt), now),
		),
	)
}

// groupHasDirectMembershipForUser keeps the claim query bounded by applying
// membership eligibility as an EXISTS predicate on the groups query itself.
func groupHasDirectMembershipForUser(userID int, now time.Time) predicate.Groups {
	return predicate.Groups(func(selector *sql.Selector) {
		membership := sql.Table(usermemberships.Table).As("claim_direct_membership")
		query := sql.Select(membership.C(usermemberships.FieldID)).
			From(membership).
			Where(sql.And(
				sql.EQ(membership.C(usermemberships.FieldUserID), userID),
				sql.EQ(membership.C(usermemberships.FieldTargetType), membershipTargetGroup),
				sql.ColumnsEQ(membership.C(usermemberships.FieldTargetID), selector.C(groups.FieldID)),
				activeMembershipSQL(membership, now),
			))
		selector.Where(sql.Exists(query))
	})
}

// groupHasDepartmentMembershipForUser resolves the active Department and its
// active membership inside the database instead of materializing every
// department ID for the user in Go.
func groupHasDepartmentMembershipForUser(userID int, now time.Time) predicate.Groups {
	return predicate.Groups(func(selector *sql.Selector) {
		membership := sql.Table(usermemberships.Table).As("claim_department_membership")
		department := sql.Table(departments.Table).As("claim_department")
		query := sql.Select(membership.C(usermemberships.FieldID)).
			From(membership).
			Join(department).
			On(membership.C(usermemberships.FieldTargetID), department.C(departments.FieldID)).
			Where(sql.And(
				sql.EQ(membership.C(usermemberships.FieldUserID), userID),
				sql.EQ(membership.C(usermemberships.FieldTargetType), membershipTargetDepartment),
				sql.ColumnsEQ(membership.C(usermemberships.FieldTargetID), selector.C(groups.FieldSourceID)),
				activeMembershipSQL(membership, now),
				sql.EQ(department.C(departments.FieldDepartmentStatus), int(adminv1.Department_ACTIVE)),
				sql.IsNull(department.C(departments.FieldDeletedAt)),
			))
		selector.Where(sql.Exists(query))
	})
}

func groupHasActiveRoleSource() predicate.Groups {
	return predicate.Groups(func(selector *sql.Selector) {
		role := sql.Table(roles.Table).As("claim_role")
		query := sql.Select(role.C(roles.FieldID)).
			From(role).
			Where(sql.And(
				sql.ColumnsEQ(role.C(roles.FieldID), selector.C(groups.FieldSourceID)),
				sql.EQ(role.C(roles.FieldRoleStatus), int(adminv1.Role_ACTIVE)),
				sql.IsNull(role.C(roles.FieldDeletedAt)),
			))
		selector.Where(sql.Exists(query))
	})
}

// groupProjectsEffectiveRoleForUser applies USER, DEPARTMENT and matched
// SYSTEM Group role bindings directly to ROLE Group rows. This avoids first
// materializing an unbounded role-ID slice only to feed it back into ID IN.
func groupProjectsEffectiveRoleForUser(userID int, matchedSystemGroupIDs []int, now time.Time) predicate.Groups {
	return predicate.Groups(func(selector *sql.Selector) {
		direct := sql.Table(principalroles.Table).As("claim_direct_role")
		directQuery := sql.Select(direct.C(principalroles.FieldID)).
			From(direct).
			Where(sql.And(
				sql.EQ(direct.C(principalroles.FieldPrincipalType), principalTypeUser),
				sql.EQ(direct.C(principalroles.FieldPrincipalID), userID),
				sql.ColumnsEQ(direct.C(principalroles.FieldRoleID), selector.C(groups.FieldSourceID)),
				activePrincipalRoleSQL(direct, now),
			))

		membership := sql.Table(usermemberships.Table).As("claim_role_department_membership")
		department := sql.Table(departments.Table).As("claim_role_department")
		departmentRole := sql.Table(principalroles.Table).As("claim_department_role")
		departmentQuery := sql.Select(membership.C(usermemberships.FieldID)).
			From(membership).
			Join(department).
			On(membership.C(usermemberships.FieldTargetID), department.C(departments.FieldID)).
			Join(departmentRole).
			On(membership.C(usermemberships.FieldTargetID), departmentRole.C(principalroles.FieldPrincipalID)).
			Where(sql.And(
				sql.EQ(membership.C(usermemberships.FieldUserID), userID),
				sql.EQ(membership.C(usermemberships.FieldTargetType), membershipTargetDepartment),
				activeMembershipSQL(membership, now),
				sql.EQ(department.C(departments.FieldDepartmentStatus), int(adminv1.Department_ACTIVE)),
				sql.IsNull(department.C(departments.FieldDeletedAt)),
				sql.EQ(departmentRole.C(principalroles.FieldPrincipalType), principalTypeDepartment),
				sql.ColumnsEQ(departmentRole.C(principalroles.FieldRoleID), selector.C(groups.FieldSourceID)),
				activePrincipalRoleSQL(departmentRole, now),
			))

		alternatives := []*sql.Predicate{sql.Exists(directQuery), sql.Exists(departmentQuery)}
		if len(matchedSystemGroupIDs) > 0 {
			systemRole := sql.Table(principalroles.Table).As("claim_system_group_role")
			systemQuery := sql.Select(systemRole.C(principalroles.FieldID)).
				From(systemRole).
				Where(sql.And(
					sql.EQ(systemRole.C(principalroles.FieldPrincipalType), principalTypeGroup),
					sql.InInts(systemRole.C(principalroles.FieldPrincipalID), matchedSystemGroupIDs...),
					sql.ColumnsEQ(systemRole.C(principalroles.FieldRoleID), selector.C(groups.FieldSourceID)),
					activePrincipalRoleSQL(systemRole, now),
				))
			alternatives = append(alternatives, sql.Exists(systemQuery))
		}
		selector.Where(sql.Or(alternatives...))
	})
}

func userHasDirectOrDepartmentRole(roleID int, now time.Time) predicate.Users {
	return predicate.Users(func(selector *sql.Selector) {
		direct := sql.Table(principalroles.Table).As("role_member_direct")
		directQuery := sql.Select(direct.C(principalroles.FieldID)).
			From(direct).
			Where(sql.And(
				sql.EQ(direct.C(principalroles.FieldPrincipalType), principalTypeUser),
				sql.ColumnsEQ(direct.C(principalroles.FieldPrincipalID), selector.C(users.FieldID)),
				sql.EQ(direct.C(principalroles.FieldRoleID), roleID),
				activePrincipalRoleSQL(direct, now),
			))

		membership := sql.Table(usermemberships.Table).As("role_member_department_membership")
		department := sql.Table(departments.Table).As("role_member_department")
		departmentRole := sql.Table(principalroles.Table).As("role_member_department_role")
		departmentQuery := sql.Select(membership.C(usermemberships.FieldID)).
			From(membership).
			Join(department).
			On(membership.C(usermemberships.FieldTargetID), department.C(departments.FieldID)).
			Join(departmentRole).
			On(membership.C(usermemberships.FieldTargetID), departmentRole.C(principalroles.FieldPrincipalID)).
			Where(sql.And(
				sql.ColumnsEQ(membership.C(usermemberships.FieldUserID), selector.C(users.FieldID)),
				sql.EQ(membership.C(usermemberships.FieldTargetType), membershipTargetDepartment),
				activeMembershipSQL(membership, now),
				sql.EQ(department.C(departments.FieldDepartmentStatus), int(adminv1.Department_ACTIVE)),
				sql.IsNull(department.C(departments.FieldDeletedAt)),
				sql.EQ(departmentRole.C(principalroles.FieldPrincipalType), principalTypeDepartment),
				sql.EQ(departmentRole.C(principalroles.FieldRoleID), roleID),
				activePrincipalRoleSQL(departmentRole, now),
			))

		selector.Where(sql.Or(sql.Exists(directQuery), sql.Exists(departmentQuery)))
	})
}

func roleGroupUserPredicates(ctx context.Context, db *lion.Client, roleID int, now time.Time) ([]predicate.Users, error) {
	roleBinding := predicate.Groups(func(selector *sql.Selector) {
		binding := sql.Table(principalroles.Table).As("role_member_system_binding")
		query := sql.Select(binding.C(principalroles.FieldID)).
			From(binding).
			Where(sql.And(
				sql.EQ(binding.C(principalroles.FieldPrincipalType), principalTypeGroup),
				sql.ColumnsEQ(binding.C(principalroles.FieldPrincipalID), selector.C(groups.FieldID)),
				sql.EQ(binding.C(principalroles.FieldRoleID), roleID),
				activePrincipalRoleSQL(binding, now),
			))
		selector.Where(sql.Exists(query))
	})
	systemGroups, err := db.Groups.Query().Select(
		groups.FieldID,
		groups.FieldGroupType,
		groups.FieldConfig,
	).Where(
		groups.GroupTypeEQ(int(adminv1.Group_SYSTEM)),
		groups.GroupStatusEQ(int(adminv1.Group_ACTIVE)),
		groups.DeletedAtIsNil(),
		roleBinding,
	).Limit(activeRuleGroupMax + 1).All(ctx)
	if err != nil {
		return nil, err
	}
	if len(systemGroups) > activeRuleGroupMax {
		return nil, errs.ResourceExhausted(ctx).WithMessage("active rule group limit exceeded")
	}
	alternatives := []predicate.Users{userHasDirectOrDepartmentRole(roleID, now)}
	for _, group := range systemGroups {
		compiled, configErr := decodeStoredUserFilter(group.Config)
		if configErr != nil {
			return nil, errs.FailedPrecondition(ctx).WithMessage(fmt.Sprintf("SYSTEM group %d has invalid rule config", group.ID))
		}
		alternatives = append(alternatives, users.And(compiled.predicates()...))
	}
	return []predicate.Users{users.DeletedAtIsNil(), users.Or(alternatives...)}, nil
}

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
