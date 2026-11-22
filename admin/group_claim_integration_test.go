package admin

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
)

// 回归测试：groups claim scope——按创建来源二分。用户创建的六类组进入
// claim：PROJECT 直接成员、DEPARTMENT 部门隶属、ROLE 角色绑定投影、
// DYNAMIC 规则命中；平台内置 SYSTEM 组（如 everyone，恒真规则）不进入。
// 若 effectiveGroupCodesForUserAt 的 ruleGroups 查询重新引入 Group_SYSTEM，
// 或用户创建的组被错误排除，本测试失败。服务端角色投影走
// matchedActiveSystemGroupIDsForUserAt，不受此约束影响。
func TestEffectiveGroupCodesClaimScopeIntegration(t *testing.T) {
	ctx := t.Context()
	db := adminIntegrationClient(t)

	tx, err := db.Tx(ctx)
	if err != nil {
		t.Fatalf("begin tx err: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 与 rpc_database.go 的 initialize 相同的种子，复用真实内置组创建路径。
	if err := ensureGroupCapacitySetting(ctx, tx); err != nil {
		t.Fatalf("ensure group capacity setting err: %v", err)
	}
	if _, err := ensureBuiltinGroup(ctx, tx, builtinGroupSeed{
		Code:        "everyone",
		DisplayName: "Everyone",
		Description: "All non-deleted users",
		UserFilter:  "status != DELETED",
		SortOrder:   10,
	}); err != nil {
		t.Fatalf("ensure everyone group err: %v", err)
	}
	// 除 everyone 外再种一个 SYSTEM 组，证明排除按组类型而非特定 code。
	if _, err := ensureBuiltinGroup(ctx, tx, builtinGroupSeed{
		Code:        "system_claim_group",
		DisplayName: "System Claim Group",
		Description: "SYSTEM group claim scope test",
		UserFilter:  "status != DELETED",
		SortOrder:   20,
	}); err != nil {
		t.Fatalf("ensure system group err: %v", err)
	}

	dynamicConfig, err := json.Marshal(storedUserFilterConfig{UserFilter: "status != DELETED"})
	if err != nil {
		t.Fatalf("marshal dynamic config err: %v", err)
	}
	if _, err := tx.Groups.Create().
		SetCode("dynamic_claim_group").
		SetDisplayName("Dynamic Claim Group").
		SetGroupType(int(adminv1.Group_DYNAMIC)).
		SetGroupStatus(int(adminv1.Group_ACTIVE)).
		SetConfig(dynamicConfig).
		Save(ctx); err != nil {
		t.Fatalf("create dynamic group err: %v", err)
	}

	projectGroup, err := tx.Groups.Create().
		SetCode("project_claim_group").
		SetDisplayName("Project Claim Group").
		SetGroupType(int(adminv1.Group_PROJECT)).
		SetGroupStatus(int(adminv1.Group_ACTIVE)).
		Save(ctx)
	if err != nil {
		t.Fatalf("create project group err: %v", err)
	}

	// DEPARTMENT/ROLE 组：先建上游实体，再复用 validateGroupTypeConfig
	// 的真实校验路径生成 config/source。
	department, err := tx.Departments.Create().
		SetCode("claim_dept").
		SetDisplayName("Claim Department").
		SetSortOrder(1).
		SetParentID(0).
		SetDepartmentStatus(int(adminv1.Department_ACTIVE)).
		Save(ctx)
	if err != nil {
		t.Fatalf("create department err: %v", err)
	}
	departmentGroup := &adminv1.Group{
		Code:        "department_claim_group",
		DisplayName: "Department Claim Group",
		Type:        adminv1.Group_DEPARTMENT,
		Status:      adminv1.Group_ACTIVE,
		Config: &adminv1.Group_DepartmentConfig_{DepartmentConfig: &adminv1.Group_DepartmentConfig{
			DepartmentId: int64(department.ID),
		}},
	}
	departmentValidated, err := validateGroupTypeConfig(ctx, tx.Client(), departmentGroup, false)
	if err != nil {
		t.Fatalf("validate department group err: %v", err)
	}
	if _, err := tx.Groups.Create().
		SetCode("department_claim_group").
		SetDisplayName("Department Claim Group").
		SetGroupType(int(adminv1.Group_DEPARTMENT)).
		SetGroupStatus(int(adminv1.Group_ACTIVE)).
		SetNillableSourceID(departmentValidated.sourceID).
		SetConfig(departmentValidated.config).
		Save(ctx); err != nil {
		t.Fatalf("create department group err: %v", err)
	}

	role, err := tx.Roles.Create().
		SetCode("claim_role").
		SetDisplayName("Claim Role").
		SetRoleStatus(int(adminv1.Role_ACTIVE)).
		Save(ctx)
	if err != nil {
		t.Fatalf("create role err: %v", err)
	}
	roleGroup := &adminv1.Group{
		Code:        "role_claim_group",
		DisplayName: "Role Claim Group",
		Type:        adminv1.Group_ROLE,
		Status:      adminv1.Group_ACTIVE,
		Config: &adminv1.Group_RoleConfig_{RoleConfig: &adminv1.Group_RoleConfig{
			RoleId: int64(role.ID),
		}},
	}
	roleValidated, err := validateGroupTypeConfig(ctx, tx.Client(), roleGroup, false)
	if err != nil {
		t.Fatalf("validate role group err: %v", err)
	}
	if _, err := tx.Groups.Create().
		SetCode("role_claim_group").
		SetDisplayName("Role Claim Group").
		SetGroupType(int(adminv1.Group_ROLE)).
		SetGroupStatus(int(adminv1.Group_ACTIVE)).
		SetNillableSourceID(roleValidated.sourceID).
		SetConfig(roleValidated.config).
		Save(ctx); err != nil {
		t.Fatalf("create role group err: %v", err)
	}

	user, err := tx.Users.Create().
		SetUsername("claim_scope_user").
		SetUserStatus(int(adminv1.User_ACTIVE)).
		Save(ctx)
	if err != nil {
		t.Fatalf("create user err: %v", err)
	}
	// PROJECT 组的直接成员行（GROUP 类型的 usermemberships）。
	if err := tx.UserMemberships.Create().
		SetUserID(user.ID).
		SetTargetType(membershipTargetGroup).
		SetTargetID(projectGroup.ID).
		SetMemberType(int(adminv1.Membership_PRIMARY.Number())).
		SetMemberRole(int(adminv1.Membership_MEMBER.Number())).
		SetMemberStatus(int(adminv1.Membership_ACTIVE.Number())).
		Exec(ctx); err != nil {
		t.Fatalf("create project membership err: %v", err)
	}
	// DEPARTMENT 组的部门隶属行。
	if err := tx.UserMemberships.Create().
		SetUserID(user.ID).
		SetTargetType(membershipTargetDepartment).
		SetTargetID(department.ID).
		SetMemberType(int(adminv1.Membership_PRIMARY.Number())).
		SetMemberRole(int(adminv1.Membership_MEMBER.Number())).
		SetMemberStatus(int(adminv1.Membership_ACTIVE.Number())).
		Exec(ctx); err != nil {
		t.Fatalf("create department membership err: %v", err)
	}
	// ROLE 组的用户角色绑定行（USER principal 直接持角色）。
	if err := tx.PrincipalRoles.Create().
		SetPrincipalType(principalTypeUser).
		SetPrincipalID(user.ID).
		SetRoleID(role.ID).
		SetBindingStatus(bindingStatusActive).
		Exec(ctx); err != nil {
		t.Fatalf("create role binding err: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit tx err: %v", err)
	}

	codes, err := effectiveGroupCodesForUserAt(ctx, db, user.ID, time.Now())
	if err != nil {
		t.Fatalf("effectiveGroupCodesForUserAt err: %v", err)
	}

	// 进 claim：用户创建的组——直接成员、部门隶属、角色绑定、规则命中。
	for _, code := range []string{"project_claim_group", "department_claim_group", "role_claim_group", "dynamic_claim_group"} {
		if !slices.Contains(codes, code) {
			t.Fatalf("expected %q in claim, codes = %v", code, codes)
		}
	}
	// 不进 claim：平台内置 SYSTEM 组（含内置 everyone）。
	for _, code := range []string{"everyone", "system_claim_group"} {
		if slices.Contains(codes, code) {
			t.Fatalf("expected SYSTEM group %q excluded from claim, codes = %v", code, codes)
		}
	}
}
