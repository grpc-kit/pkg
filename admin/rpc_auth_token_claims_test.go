package admin

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/rpc"
)

// callerContext 构造一个携带调用者 roles/groups/tenant 的请求上下文。
func callerContext(roles, groups []string, tenant string) context.Context {
	ctx := context.Background()
	ctx = rpc.ContextWithRoles(ctx, roles)
	ctx = rpc.ContextWithGroups(ctx, groups)
	claims := auth.AccessTokenClaims{CommonClaims: auth.CommonClaims{Tenant: tenant}}
	claims.SetSubject("1")
	return rpc.ContextWithTokenClaims(ctx, claims)
}

// sameStrings 做集合相等比较，忽略顺序（BuildAccessTokenClaims 会对 roles/groups 排序）。
func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
		if seen[v] < 0 {
			return false
		}
	}
	return true
}

func TestResolveAuthTokenClaimOverridesSuperadminOverrides(t *testing.T) {
	api := New()
	ctx := callerContext([]string{"superadmin"}, []string{"caller-group"}, "acme")
	req := &adminv1.CreateAuthTokenRequest{
		Tenant: "custom-tenant",
		Roles:  []string{"role-a", "role-b"},
		Groups: []string{"group-a"},
	}
	o, err := api.resolveAuthTokenClaimOverrides(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.Tenant != "custom-tenant" {
		t.Fatalf("tenant = %q, want custom-tenant", o.Tenant)
	}
	if !sameStrings(o.Roles, []string{"role-a", "role-b"}) {
		t.Fatalf("roles = %v, want [role-a role-b]", o.Roles)
	}
	if !sameStrings(o.Groups, []string{"group-a"}) {
		t.Fatalf("groups = %v, want [group-a]", o.Groups)
	}
}

// TestResolveAuthTokenClaimOverridesSuperadminBlankOmitsClaims 验证 superadmin 留空
// tenant/roles/groups 时返回空值（令牌中省略对应声明），不再回退到静态用户配置。
func TestResolveAuthTokenClaimOverridesSuperadminBlankOmitsClaims(t *testing.T) {
	api := New()
	ctx := callerContext([]string{"superadmin"}, nil, "acme")
	req := &adminv1.CreateAuthTokenRequest{}
	o, err := api.resolveAuthTokenClaimOverrides(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.Tenant != "" || o.Roles != nil || o.Groups != nil {
		t.Fatalf("superadmin blank must omit claims: tenant=%q roles=%v groups=%v", o.Tenant, o.Roles, o.Groups)
	}
}

// TestResolveAuthTokenClaimOverridesSuperadminOverridesIdentityFields 验证 superadmin
// 可自定义 preferred_username/email 身份展示字段（subject 委托签发在 CreateAuthToken 主流程处理）。
func TestResolveAuthTokenClaimOverridesSuperadminOverridesIdentityFields(t *testing.T) {
	api := New()
	ctx := callerContext([]string{"superadmin"}, nil, "acme")
	req := &adminv1.CreateAuthTokenRequest{
		Username:      "display-name",
		Email:         "display@example.com",
		EmailVerified: true,
	}
	o, err := api.resolveAuthTokenClaimOverrides(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.PreferredUsername != "display-name" || o.Email != "display@example.com" {
		t.Fatalf("identity overrides mismatch: preferred=%q email=%q", o.PreferredUsername, o.Email)
	}
	if !o.EmailVerified {
		t.Fatalf("email_verified = %v, want true", o.EmailVerified)
	}
}

// TestResolveAuthTokenClaimOverridesNonSuperadminBlankOmitsClaims 验证非 superadmin 留空
// tenant/roles/groups 时返回空值（令牌中省略），不再回退到调用者自身能力。
func TestResolveAuthTokenClaimOverridesNonSuperadminBlankOmitsClaims(t *testing.T) {
	api := New()
	callerRoles := []string{"r1", "r2"}
	callerGroups := []string{"g1"}
	ctx := callerContext(callerRoles, callerGroups, "acme")
	req := &adminv1.CreateAuthTokenRequest{}
	o, err := api.resolveAuthTokenClaimOverrides(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.Tenant != "" || o.Roles != nil || o.Groups != nil {
		t.Fatalf("non-superadmin blank must omit claims: tenant=%q roles=%v groups=%v", o.Tenant, o.Roles, o.Groups)
	}
}

// TestResolveAuthTokenClaimOverridesNonSuperadminIgnoresIdentityFields 验证非 superadmin
// 传入身份展示字段时被忽略（返回空），强制使用调用方自身值。
func TestResolveAuthTokenClaimOverridesNonSuperadminIgnoresIdentityFields(t *testing.T) {
	api := New()
	ctx := callerContext([]string{"r1"}, nil, "acme")
	req := &adminv1.CreateAuthTokenRequest{
		Username: "should-be-ignored",
		Email:    "ignored@example.com",
	}
	o, err := api.resolveAuthTokenClaimOverrides(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.PreferredUsername != "" || o.Email != "" {
		t.Fatalf("non-superadmin identity fields must be ignored: preferred=%q email=%q", o.PreferredUsername, o.Email)
	}
}

func TestResolveAuthTokenClaimOverridesNonSuperadminSubsetAllowed(t *testing.T) {
	api := New()
	ctx := callerContext([]string{"r1", "r2"}, []string{"g1", "g2"}, "acme")
	req := &adminv1.CreateAuthTokenRequest{
		Tenant: "acme",
		Roles:  []string{"r1"},
		Groups: []string{"g2"},
	}
	o, err := api.resolveAuthTokenClaimOverrides(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if o.Tenant != "acme" || !sameStrings(o.Roles, []string{"r1"}) || !sameStrings(o.Groups, []string{"g2"}) {
		t.Fatalf("subset allowed mismatch: tenant=%q roles=%v groups=%v", o.Tenant, o.Roles, o.Groups)
	}
}

func TestResolveAuthTokenClaimOverridesNonSuperadminRolesExceedScope(t *testing.T) {
	api := New()
	ctx := callerContext([]string{"r1"}, nil, "acme")
	req := &adminv1.CreateAuthTokenRequest{Roles: []string{"r1", "r2"}}
	_, err := api.resolveAuthTokenClaimOverrides(ctx, req)
	assertPermissionDenied(t, err)
}

func TestResolveAuthTokenClaimOverridesNonSuperadminGroupsExceedScope(t *testing.T) {
	api := New()
	ctx := callerContext([]string{"r1"}, []string{"g1"}, "acme")
	req := &adminv1.CreateAuthTokenRequest{Groups: []string{"g2"}}
	_, err := api.resolveAuthTokenClaimOverrides(ctx, req)
	assertPermissionDenied(t, err)
}

func TestResolveAuthTokenClaimOverridesNonSuperadminTenantMismatch(t *testing.T) {
	api := New()
	ctx := callerContext([]string{"r1"}, nil, "acme")
	req := &adminv1.CreateAuthTokenRequest{Tenant: "other"}
	_, err := api.resolveAuthTokenClaimOverrides(ctx, req)
	assertPermissionDenied(t, err)
}

// TestStaticUserIssueAccessTokenOverridesClaims 验证 issuance 中的 tenant/roles/groups
// 非空时作为最终声明写入令牌（CreateAuthToken 授权决策的最终值由此传入）。
func TestStaticUserIssueAccessTokenOverridesClaims(t *testing.T) {
	const passwordHash = "override-password-hash"
	user := StaticUser{
		UserID:       5,
		Username:     "u",
		PasswordHash: passwordHash,
		Roles:        []string{"static-role"},
		Groups:       []string{"static-group"},
		Tenant:       "static-tenant",
	}
	issuance := AccessTokenIssuanceContext{
		ClientID: "client-x",
		Tenant:   "override-tenant",
		Roles:    []string{"override-role"},
		Groups:   []string{"override-group"},
		TTL:      time.Hour,
	}

	tokenString, err := user.issueAccessToken(issuance)
	if err != nil {
		t.Fatalf("issueAccessToken: %v", err)
	}

	var claims auth.AccessTokenClaims
	if _, err := jwt.ParseWithClaims(tokenString, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(passwordHash), nil
	}); err != nil {
		t.Fatalf("ParseWithClaims: %v", err)
	}
	if claims.Tenant != "override-tenant" {
		t.Fatalf("tenant = %q, want override-tenant", claims.Tenant)
	}
	if !sameStrings(claims.Roles, []string{"override-role"}) {
		t.Fatalf("roles = %v, want [override-role]", claims.Roles)
	}
	if !sameStrings(claims.Groups, []string{"override-group"}) {
		t.Fatalf("groups = %v, want [override-group]", claims.Groups)
	}
	if claims.ClientID != "client-x" {
		t.Fatalf("client_id = %q, want client-x", claims.ClientID)
	}
}

// TestStaticUserIssueAccessTokenOverridesIdentityFields 验证 issuance 中的身份展示字段
// 非空时覆盖静态用户自身值（superadmin 自定义场景），subject 仍为静态用户 userID。
func TestStaticUserIssueAccessTokenOverridesIdentityFields(t *testing.T) {
	const passwordHash = "identity-password-hash"
	user := StaticUser{
		UserID:       42,
		Username:     "real-username",
		PasswordHash: passwordHash,
		Email:        "real@example.com",
	}
	issuance := AccessTokenIssuanceContext{
		ClientID:          "client-x",
		PreferredUsername: "custom-display",
		Email:             "custom@example.com",
		TTL:               time.Hour,
	}

	tokenString, err := user.issueAccessToken(issuance)
	if err != nil {
		t.Fatalf("issueAccessToken: %v", err)
	}

	var claims auth.AccessTokenClaims
	if _, err := jwt.ParseWithClaims(tokenString, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(passwordHash), nil
	}); err != nil {
		t.Fatalf("ParseWithClaims: %v", err)
	}
	if claims.PreferredUsername != "custom-display" {
		t.Fatalf("preferred_username = %q, want custom-display", claims.PreferredUsername)
	}
	if claims.Email != "custom@example.com" {
		t.Fatalf("email = %q, want custom@example.com", claims.Email)
	}
	// subject 不受身份字段覆盖影响，仍为静态用户 userID。
	if claims.Subject != "42" {
		t.Fatalf("subject = %q, want 42", claims.Subject)
	}
}
