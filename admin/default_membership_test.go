package admin

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/oauth2"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/usermemberships"
	"github.com/grpc-kit/pkg/lion/users"
)

// 集成测试门控：默认跳过，设置 GRPC_KIT_ADMIN_DB_INTEGRATION=1 启用。
// 数据库取 GRPC_KIT_ADMIN_DB_DSN（默认 testbed 本地 PostgreSQL 容器，
// 见 testbed/docs/dev/postgres.md）。测试在服务器上创建独立的临时库，
// 不触碰 DSN 所指库中的数据。
const (
	adminDBIntegrationEnv    = "GRPC_KIT_ADMIN_DB_INTEGRATION"
	adminDBIntegrationDSNEnv = "GRPC_KIT_ADMIN_DB_DSN"
	adminDBIntegrationDSN    = "postgres://testbed:testbed@127.0.0.1:5432/testbed?sslmode=disable"

	// 32 字节测试密钥，满足 crypto.validateAESKey 约束。
	adminTestAESKey = "0123456789abcdef0123456789abcdef"
)

// adminIntegrationClient 创建独立的临时数据库并返回完成 schema 迁移的 lion 客户端。
// 清理顺序（t.Cleanup LIFO）：先关客户端连接，再 DROP 临时库。
func adminIntegrationClient(t *testing.T) *lion.Client {
	t.Helper()

	if os.Getenv(adminDBIntegrationEnv) == "" {
		t.Skipf("skip external database integration test; set %s=1 to enable", adminDBIntegrationEnv)
	}

	dsn := os.Getenv(adminDBIntegrationDSNEnv)
	if dsn == "" {
		dsn = adminDBIntegrationDSN
	}
	baseURL, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse integration dsn err: %v", err)
	}
	dbName := fmt.Sprintf("admin_test_%d", time.Now().UnixNano())

	serverDB, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open database server err: %v", err)
	}
	if _, err := serverDB.Exec(fmt.Sprintf(`CREATE DATABASE %q`, dbName)); err != nil {
		_ = serverDB.Close()
		t.Fatalf("create ephemeral database %s err: %v", dbName, err)
	}
	t.Cleanup(func() {
		if _, dropErr := serverDB.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %q WITH (FORCE)`, dbName)); dropErr != nil {
			t.Logf("drop ephemeral database %s err: %v", dbName, dropErr)
		}
		_ = serverDB.Close()
	})

	clientURL := *baseURL
	clientURL.Path = "/" + dbName
	client, err := lion.Open("postgres", clientURL.String())
	if err != nil {
		t.Fatalf("open lion client err: %v", err)
	}
	if err := client.Schema.Create(context.Background()); err != nil {
		_ = client.Close()
		t.Fatalf("lion migrate err: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	return client
}

// createTestAuthProvider 写入一条最小可用的 auth provider 行（仅 code 与 provider_type 必填）。
func createTestAuthProvider(t *testing.T, db *lion.Client, code string, providerType adminv1.AuthProvider_Type) *lion.AuthProviders {
	t.Helper()

	ap, err := db.AuthProviders.Create().
		SetCode(code).
		SetProviderType(int(providerType)).
		Save(context.Background())
	if err != nil {
		t.Fatalf("create auth provider %s err: %v", code, err)
	}
	return ap
}

// newTestSocialUsers 构造仅含测试所需字段的 socialUsers（先例：social_users_oidc_test.go）。
func newTestSocialUsers(db *lion.Client, ap *lion.AuthProviders) *socialUsers {
	return &socialUsers{
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		db:           db,
		aesKey:       []byte(adminTestAESKey),
		ProviderName: ap.Code,
		AuthProvider: ap,
	}
}

func unassignedDeptID(t *testing.T, db *lion.Client) int {
	t.Helper()

	dept, err := db.Departments.Query().
		Where(departments.CodeEQ(seedDepartmentCode(adminv1.DepartmentCode_DEPARTMENT_CODE_UNASSIGNED))).
		Only(context.Background())
	if err != nil {
		t.Fatalf("query unassigned department err: %v", err)
	}
	return dept.ID
}

func departmentMembershipsOf(t *testing.T, db *lion.Client, userID int) []*lion.UserMemberships {
	t.Helper()

	list, err := db.UserMemberships.Query().
		Where(
			usermemberships.UserIDEQ(userID),
			usermemberships.TargetTypeEQ(membershipTargetDepartment),
		).
		All(context.Background())
	if err != nil {
		t.Fatalf("query department memberships of user %d err: %v", userID, err)
	}
	return list
}

// assertUnassignedMembership 断言用户恰好有一条部门成员关系，且指向待分配部门，
// 取值与 CreateUser 默认归属一致（MEMBER/ACTIVE/PRIMARY，created_by=0）。
func assertUnassignedMembership(t *testing.T, db *lion.Client, userID int) {
	t.Helper()

	list := departmentMembershipsOf(t, db, userID)
	if len(list) != 1 {
		t.Fatalf("user %d should have exactly one department membership, got %d", userID, len(list))
	}
	m := list[0]
	if m.TargetID != unassignedDeptID(t, db) {
		t.Fatalf("user %d membership target %d is not the unassigned department", userID, m.TargetID)
	}
	if m.MemberRole != int(adminv1.Membership_MEMBER) {
		t.Fatalf("user %d member_role = %d, want MEMBER(%d)", userID, m.MemberRole, int(adminv1.Membership_MEMBER))
	}
	if m.MemberStatus != int(adminv1.Membership_ACTIVE) {
		t.Fatalf("user %d member_status = %d, want ACTIVE(%d)", userID, m.MemberStatus, int(adminv1.Membership_ACTIVE))
	}
	if m.MemberType != int(adminv1.Membership_PRIMARY) {
		t.Fatalf("user %d member_type = %d, want PRIMARY(%d)", userID, m.MemberType, int(adminv1.Membership_PRIMARY))
	}
	if m.CreatedBy != 0 {
		t.Fatalf("user %d membership created_by = %d, want 0 (system provisioning)", userID, m.CreatedBy)
	}
}

func TestUnassignedMembershipProvisioningIntegration(t *testing.T) {
	db := adminIntegrationClient(t)
	ctx := context.Background()

	api := New(WithLionClient(db), WithAESKey([]byte(adminTestAESKey)))
	if _, err := api.CreateDatabaseInitialize(ctx, &adminv1.CreateDatabaseInitializeRequest{}); err != nil {
		t.Fatalf("database initialize err: %v", err)
	}

	// 初始化种子：admin 用户挂 admin 部门，而非待分配部门。
	adminUser, err := db.Users.Query().
		Where(users.UsernameEQ(seedBootstrapUsername(adminv1.BootstrapUsername_BOOTSTRAP_USERNAME_ADMIN))).
		Only(ctx)
	if err != nil {
		t.Fatalf("query seed admin user err: %v", err)
	}
	adminMemberships := departmentMembershipsOf(t, db, adminUser.ID)
	if len(adminMemberships) != 1 {
		t.Fatalf("seed admin user should have exactly one department membership, got %d", len(adminMemberships))
	}
	if adminMemberships[0].TargetID == unassignedDeptID(t, db) {
		t.Fatal("seed admin user should belong to the admin department, not unassigned")
	}

	// LDAP 首次登录建档：email 为空 + phone 为 nil，不触发 verified identifier 自动关联。
	ldapAP := createTestAuthProvider(t, db, "testldap", adminv1.AuthProvider_LDAP)
	ldapS := newTestSocialUsers(db, ldapAP)
	ldapUserID, err := ldapS.provisionLDAPUserOnFirstLogin(
		ctx, "1001", "mingqing", &ldapUserAttrs{DisplayName: "Integration LDAP"}, nil)
	if err != nil {
		t.Fatalf("provision ldap user err: %v", err)
	}
	assertUnassignedMembership(t, db, ldapUserID)

	// OIDC 首次登录建档：oauth2Token 必须非 nil（新建分支解引用），email 为空不触发自动关联。
	oidcAP := createTestAuthProvider(t, db, "testoidc", adminv1.AuthProvider_OIDC)
	oidcS := newTestSocialUsers(db, oidcAP)
	oidcUserID, err := oidcS.upsertUserOIDC(ctx, &oauth2.Token{}, externalUserClaims{
		ProviderSubject: "oidc-sub-1",
		Username:        "oidcalice",
		Nickname:        "Alice",
	})
	if err != nil {
		t.Fatalf("upsert oidc user err: %v", err)
	}
	assertUnassignedMembership(t, db, oidcUserID)

	// 微信首次登录建档。
	wechatAP := createTestAuthProvider(t, db, "testwechat", adminv1.AuthProvider_WECHAT)
	wechatS := newTestSocialUsers(db, wechatAP)
	wechatUserID, err := wechatS.upsertUserWechat(ctx, &wechatCode2SessionResponse{
		Openid:     "openid-int-1",
		SessionKey: "sess-key-1",
	})
	if err != nil {
		t.Fatalf("upsert wechat user err: %v", err)
	}
	assertUnassignedMembership(t, db, wechatUserID)

	// 存量回填：无任何部门归属的用户在重跑初始化后补挂待分配部门。
	orphan, err := db.Users.Create().SetUsername("orphan_user_1").Save(ctx)
	if err != nil {
		t.Fatalf("create orphan user err: %v", err)
	}
	if _, err := api.CreateDatabaseInitialize(ctx, &adminv1.CreateDatabaseInitializeRequest{}); err != nil {
		t.Fatalf("database initialize (backfill) err: %v", err)
	}
	assertUnassignedMembership(t, db, orphan.ID)

	// 幂等：再次重跑初始化不产生重复的部门成员关系。
	deptCount := func(userID int) int { return len(departmentMembershipsOf(t, db, userID)) }
	before := map[int]int{
		ldapUserID:   deptCount(ldapUserID),
		oidcUserID:   deptCount(oidcUserID),
		wechatUserID: deptCount(wechatUserID),
		orphan.ID:    deptCount(orphan.ID),
		adminUser.ID: deptCount(adminUser.ID),
	}
	if _, err := api.CreateDatabaseInitialize(ctx, &adminv1.CreateDatabaseInitializeRequest{}); err != nil {
		t.Fatalf("database initialize (idempotence) err: %v", err)
	}
	for userID, want := range before {
		if got := deptCount(userID); got != want {
			t.Fatalf("user %d department membership count changed from %d to %d after re-initialize", userID, want, got)
		}
	}
}

// TestUnassignedMembershipSkippedWithoutSeedIntegration 钉住降级语义：
// 数据库未初始化（无内置部门）时，登录建档不被阻断，只是跳过默认部门成员关系。
func TestUnassignedMembershipSkippedWithoutSeedIntegration(t *testing.T) {
	db := adminIntegrationClient(t) // 只建 schema，不跑初始化
	ctx := context.Background()

	ap := createTestAuthProvider(t, db, "testldap", adminv1.AuthProvider_LDAP)
	s := newTestSocialUsers(db, ap)

	userID, err := s.provisionLDAPUserOnFirstLogin(
		ctx, "uid-1", "noseed", &ldapUserAttrs{DisplayName: "No Seed"}, nil)
	if err != nil {
		t.Fatalf("provision should not fail when builtin departments are missing, err: %v", err)
	}
	if userID == 0 {
		t.Fatal("provision should return a user id")
	}

	if _, err := db.Users.Get(ctx, userID); err != nil {
		t.Fatalf("provisioned user should exist, err: %v", err)
	}
	identityCount, err := db.UserIdentities.Query().
		Where(
			useridentities.UserIDEQ(userID),
			useridentities.ProviderIDEQ(ap.ID),
		).
		Count(ctx)
	if err != nil {
		t.Fatalf("query provisioned identity err: %v", err)
	}
	if identityCount != 1 {
		t.Fatalf("provisioned user should have exactly one identity, got %d", identityCount)
	}
	if got := len(departmentMembershipsOf(t, db, userID)); got != 0 {
		t.Fatalf("expected no department membership when unassigned department is missing, got %d", got)
	}
}
