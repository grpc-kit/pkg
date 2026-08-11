package admin

import (
	"context"
	"strconv"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/rpc"
)

// callerTokenContext 构造一个携带调用方 access token 声明（username/userID/roles/groups/tenant）
// 的请求上下文，模拟拦截器在 CreateAuthToken（不再免认证）上校验 bearer 后的注入结果。
func callerTokenContext(username string, userID int64, roles, groups []string, tenant string) context.Context {
	ctx := context.Background()
	ctx = rpc.ContextWithRoles(ctx, roles)
	ctx = rpc.ContextWithGroups(ctx, groups)
	claims := auth.AccessTokenClaims{CommonClaims: auth.CommonClaims{
		PreferredUsername: username,
		Tenant:            tenant,
	}}
	claims.SetSubject(strconv.FormatInt(userID, 10))
	return rpc.ContextWithTokenClaims(ctx, claims)
}

// assertStatusCode 断言错误对应的 HTTP 状态码。
func assertStatusCode(t *testing.T, err error, want int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %d error, got nil", want)
	}
	st := errs.FromError(err)
	if st.HTTPStatusCode() != want {
		t.Fatalf("expected status %d, got %d (err: %v)", want, st.HTTPStatusCode(), err)
	}
}

const (
	testStaticUsername = "alice"
	testStaticUserID   = int64(10)
	testStaticPassword = "alice-password-hash"
)

func staticUserAPI() *KnownAdminAPI {
	users := &StaticUsers{
		&StaticUser{UserID: testStaticUserID, Username: testStaticUsername, PasswordHash: testStaticPassword},
	}
	return New(WithStaticUsers(users))
}

// TestCreateAuthTokenRequiresClientID 验证 client_id 缺失返回 400。
func TestCreateAuthTokenRequiresClientID(t *testing.T) {
	api := staticUserAPI()
	ctx := callerTokenContext(testStaticUsername, testStaticUserID, []string{"superadmin"}, nil, "")
	_, err := api.CreateAuthToken(ctx, &adminv1.CreateAuthTokenRequest{})
	assertStatusCode(t, err, 400)
}

// TestCreateAuthTokenRequiresAccessToken 验证无调用方 access token（拦截器未注入）返回 401。
func TestCreateAuthTokenRequiresAccessToken(t *testing.T) {
	api := staticUserAPI()
	_, err := api.CreateAuthToken(context.Background(), &adminv1.CreateAuthTokenRequest{ClientId: "c"})
	assertStatusCode(t, err, 401)
}

// TestCreateAuthTokenStaticUserSelfReissue 验证静态用户调用方走 HS256 重签：
// 令牌签发给调用方自己，subject 为静态用户 userID，claims 使用授权决策值（留空即省略）。
func TestCreateAuthTokenStaticUserSelfReissue(t *testing.T) {
	api := staticUserAPI()
	ctx := callerTokenContext(testStaticUsername, testStaticUserID, []string{"superadmin"}, nil, "")
	req := &adminv1.CreateAuthTokenRequest{
		ClientId:  "test-client",
		ExpiresIn: 3600,
		Tenant:    "custom-tenant",
		Roles:     []string{"role-a"},
		Groups:    []string{"group-a"},
	}
	resp, err := api.CreateAuthToken(ctx, req)
	if err != nil {
		t.Fatalf("CreateAuthToken: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("empty access token")
	}
	var claims auth.AccessTokenClaims
	token, err := jwt.ParseWithClaims(resp.AccessToken, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(testStaticPassword), nil
	})
	if err != nil || !token.Valid {
		t.Fatalf("parse token: err=%v valid=%v", err, token.Valid)
	}
	if claims.Subject != strconv.FormatInt(testStaticUserID, 10) {
		t.Fatalf("subject = %q, want %d", claims.Subject, testStaticUserID)
	}
	if claims.ClientID != "test-client" {
		t.Fatalf("client_id = %q, want test-client", claims.ClientID)
	}
	if claims.Tenant != "custom-tenant" {
		t.Fatalf("tenant = %q, want custom-tenant", claims.Tenant)
	}
	if !sameStrings(claims.Roles, []string{"role-a"}) {
		t.Fatalf("roles = %v, want [role-a]", claims.Roles)
	}
	if !sameStrings(claims.Groups, []string{"group-a"}) {
		t.Fatalf("groups = %v, want [group-a]", claims.Groups)
	}
}

// TestCreateAuthTokenStaticUserOmitsClaimsWhenBlank 验证 superadmin 留空 tenant/roles/groups
// 时重签的令牌省略这些声明。
func TestCreateAuthTokenStaticUserOmitsClaimsWhenBlank(t *testing.T) {
	api := staticUserAPI()
	ctx := callerTokenContext(testStaticUsername, testStaticUserID, []string{"superadmin"}, nil, "")
	req := &adminv1.CreateAuthTokenRequest{ClientId: "test-client", ExpiresIn: 3600}
	resp, err := api.CreateAuthToken(ctx, req)
	if err != nil {
		t.Fatalf("CreateAuthToken: %v", err)
	}
	var claims auth.AccessTokenClaims
	if _, err := jwt.ParseWithClaims(resp.AccessToken, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(testStaticPassword), nil
	}); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if claims.Tenant != "" || len(claims.Roles) != 0 || len(claims.Groups) != 0 {
		t.Fatalf("expected omitted claims, got tenant=%q roles=%v groups=%v", claims.Tenant, claims.Roles, claims.Groups)
	}
}

// TestCreateAuthTokenSuperadminBlankOmitsIdentityFields 验证 superadmin 留空
// username/email 时重签的令牌省略这些身份展示声明（不回退到调用方自身值）。
func TestCreateAuthTokenSuperadminBlankOmitsIdentityFields(t *testing.T) {
	users := &StaticUsers{
		&StaticUser{UserID: testStaticUserID, Username: testStaticUsername, PasswordHash: testStaticPassword, Email: "alice@example.com"},
	}
	api := New(WithStaticUsers(users))
	ctx := callerTokenContext(testStaticUsername, testStaticUserID, []string{"superadmin"}, nil, "")
	req := &adminv1.CreateAuthTokenRequest{ClientId: "test-client", ExpiresIn: 3600}
	resp, err := api.CreateAuthToken(ctx, req)
	if err != nil {
		t.Fatalf("CreateAuthToken: %v", err)
	}
	var claims auth.AccessTokenClaims
	if _, err := jwt.ParseWithClaims(resp.AccessToken, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(testStaticPassword), nil
	}); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if claims.PreferredUsername != "" {
		t.Fatalf("preferred_username = %q, want empty (omitted, no fallback to caller's own)", claims.PreferredUsername)
	}
	if claims.Email != "" {
		t.Fatalf("email = %q, want empty (omitted, no fallback to caller's own)", claims.Email)
	}
	if claims.Subject != strconv.FormatInt(testStaticUserID, 10) {
		t.Fatalf("subject = %q, want %d", claims.Subject, testStaticUserID)
	}
}

// TestCreateAuthTokenNonSuperadminBlankFallsBackToSelf 验证非 superadmin 留空
// username/email 时令牌回退到调用方自身值（与 superadmin 留空即省略的行为对照）。
func TestCreateAuthTokenNonSuperadminBlankFallsBackToSelf(t *testing.T) {
	users := &StaticUsers{
		&StaticUser{UserID: testStaticUserID, Username: testStaticUsername, PasswordHash: testStaticPassword, Email: "alice@example.com"},
	}
	api := New(WithStaticUsers(users))
	ctx := callerTokenContext(testStaticUsername, testStaticUserID, []string{"r1"}, nil, "")
	req := &adminv1.CreateAuthTokenRequest{ClientId: "test-client", ExpiresIn: 3600}
	resp, err := api.CreateAuthToken(ctx, req)
	if err != nil {
		t.Fatalf("CreateAuthToken: %v", err)
	}
	var claims auth.AccessTokenClaims
	if _, err := jwt.ParseWithClaims(resp.AccessToken, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(testStaticPassword), nil
	}); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if claims.PreferredUsername != testStaticUsername {
		t.Fatalf("preferred_username = %q, want %q (fallback to caller's own)", claims.PreferredUsername, testStaticUsername)
	}
	if claims.Email != "alice@example.com" {
		t.Fatalf("email = %q, want alice@example.com (fallback to caller's own)", claims.Email)
	}
}

// TestCreateAuthTokenSuperadminOverridesIdentityFields 验证 superadmin 自定义
// preferred_username/email 后令牌携带这些覆盖值；未指定 subject 时仍为调用方 userID。
func TestCreateAuthTokenSuperadminOverridesIdentityFields(t *testing.T) {
	api := staticUserAPI()
	ctx := callerTokenContext(testStaticUsername, testStaticUserID, []string{"superadmin"}, nil, "")
	req := &adminv1.CreateAuthTokenRequest{
		ClientId:  "test-client",
		ExpiresIn: 3600,
		Username:  "custom-display",
		Email:     "custom@example.com",
	}
	resp, err := api.CreateAuthToken(ctx, req)
	if err != nil {
		t.Fatalf("CreateAuthToken: %v", err)
	}
	var claims auth.AccessTokenClaims
	if _, err := jwt.ParseWithClaims(resp.AccessToken, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(testStaticPassword), nil
	}); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if claims.PreferredUsername != "custom-display" {
		t.Fatalf("preferred_username = %q, want custom-display", claims.PreferredUsername)
	}
	if claims.Email != "custom@example.com" {
		t.Fatalf("email = %q, want custom@example.com", claims.Email)
	}
	if claims.Subject != strconv.FormatInt(testStaticUserID, 10) {
		t.Fatalf("subject = %q, want %d (must stay caller's own)", claims.Subject, testStaticUserID)
	}
}

// TestCreateAuthTokenSuperadminEmailVerified 验证 superadmin 设置 email 且
// email_verified=true 时令牌携带 email_verified=true；未设置 email 时该声明不写入。
func TestCreateAuthTokenSuperadminEmailVerified(t *testing.T) {
	api := staticUserAPI()
	ctx := callerTokenContext(testStaticUsername, testStaticUserID, []string{"superadmin"}, nil, "")

	// 设置 email + email_verified=true：令牌应携带 email_verified=true。
	resp, err := api.CreateAuthToken(ctx, &adminv1.CreateAuthTokenRequest{
		ClientId:      "test-client",
		ExpiresIn:     3600,
		Email:         "custom@example.com",
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("CreateAuthToken: %v", err)
	}
	var claims auth.AccessTokenClaims
	if _, err := jwt.ParseWithClaims(resp.AccessToken, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(testStaticPassword), nil
	}); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if claims.Email != "custom@example.com" {
		t.Fatalf("email = %q, want custom@example.com", claims.Email)
	}
	if !claims.EmailVerified {
		t.Fatalf("email_verified = %v, want true", claims.EmailVerified)
	}

	// 留空 email：email_verified 不应被合成写入（即便 email_verified=true）。
	resp2, err := api.CreateAuthToken(ctx, &adminv1.CreateAuthTokenRequest{
		ClientId:      "test-client",
		ExpiresIn:     3600,
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("CreateAuthToken (no email): %v", err)
	}
	var claims2 auth.AccessTokenClaims
	if _, err := jwt.ParseWithClaims(resp2.AccessToken, &claims2, func(*jwt.Token) (interface{}, error) {
		return []byte(testStaticPassword), nil
	}); err != nil {
		t.Fatalf("parse token (no email): %v", err)
	}
	if claims2.Email != "" || claims2.EmailVerified {
		t.Fatalf("missing email must not synthesize email_verified: email=%q verified=%t", claims2.Email, claims2.EmailVerified)
	}
}

// TestCreateAuthTokenSuperadminDelegatedSubject 验证 superadmin 通过 subject
// 委托签发：指定目标 user_id 后，令牌使用目标静态用户的密钥签名，sub=目标 user_id。
func TestCreateAuthTokenSuperadminDelegatedSubject(t *testing.T) {
	const (
		targetUserID   = int64(77)
		targetUsername = "bob"
		targetPassword = "bob-password-hash"
	)
	users := &StaticUsers{
		&StaticUser{UserID: testStaticUserID, Username: testStaticUsername, PasswordHash: testStaticPassword},
		&StaticUser{UserID: targetUserID, Username: targetUsername, PasswordHash: targetPassword},
	}
	api := New(WithStaticUsers(users))
	// 调用方为 alice（superadmin），但委托签发给 bob。
	ctx := callerTokenContext(testStaticUsername, testStaticUserID, []string{"superadmin"}, nil, "")
	resp, err := api.CreateAuthToken(ctx, &adminv1.CreateAuthTokenRequest{
		ClientId:  "test-client",
		ExpiresIn: 3600,
		Subject:   strconv.FormatInt(targetUserID, 10),
	})
	if err != nil {
		t.Fatalf("CreateAuthToken: %v", err)
	}
	// 令牌必须用目标用户（bob）的密钥签名验证通过。
	var claims auth.AccessTokenClaims
	if _, err := jwt.ParseWithClaims(resp.AccessToken, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(targetPassword), nil
	}); err != nil {
		t.Fatalf("parse token with target key: %v", err)
	}
	if claims.Subject != strconv.FormatInt(targetUserID, 10) {
		t.Fatalf("subject = %q, want %d (delegated target)", claims.Subject, targetUserID)
	}
	if claims.ClientID != "test-client" {
		t.Fatalf("client_id = %q, want test-client", claims.ClientID)
	}
}

// TestCreateAuthTokenSuperadminInvalidSubject 验证 superadmin 传入非法 subject
// （非正整数）返回 400。
func TestCreateAuthTokenSuperadminInvalidSubject(t *testing.T) {
	api := staticUserAPI()
	ctx := callerTokenContext(testStaticUsername, testStaticUserID, []string{"superadmin"}, nil, "")
	for _, raw := range []string{"not-a-number", "0", "-5"} {
		_, err := api.CreateAuthToken(ctx, &adminv1.CreateAuthTokenRequest{
			ClientId:  "test-client",
			ExpiresIn: 3600,
			Subject:   raw,
		})
		assertStatusCode(t, err, 400)
	}
}

// TestCreateAuthTokenNonSuperadminSubjectIgnored 验证非 superadmin 传入 subject
// 被忽略，令牌仍签发给调用方自身（sub=调用方 userID，用调用方密钥签名）。
func TestCreateAuthTokenNonSuperadminSubjectIgnored(t *testing.T) {
	const targetUserID = int64(77)
	users := &StaticUsers{
		&StaticUser{UserID: testStaticUserID, Username: testStaticUsername, PasswordHash: testStaticPassword},
		&StaticUser{UserID: targetUserID, Username: "bob", PasswordHash: "bob-password-hash"},
	}
	api := New(WithStaticUsers(users))
	ctx := callerTokenContext(testStaticUsername, testStaticUserID, []string{"r1"}, nil, "")
	resp, err := api.CreateAuthToken(ctx, &adminv1.CreateAuthTokenRequest{
		ClientId:  "test-client",
		ExpiresIn: 3600,
		Subject:   strconv.FormatInt(targetUserID, 10),
	})
	if err != nil {
		t.Fatalf("CreateAuthToken: %v", err)
	}
	var claims auth.AccessTokenClaims
	if _, err := jwt.ParseWithClaims(resp.AccessToken, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(testStaticPassword), nil
	}); err != nil {
		t.Fatalf("parse token with caller key: %v", err)
	}
	if claims.Subject != strconv.FormatInt(testStaticUserID, 10) {
		t.Fatalf("subject = %q, want %d (non-superadmin cannot delegate)", claims.Subject, testStaticUserID)
	}
}

// TestCreateAuthTokenUnknownCallerRejected 验证调用方既非静态用户、又无 DB 时拒绝（401）。
func TestCreateAuthTokenUnknownCallerRejected(t *testing.T) {
	api := staticUserAPI()
	ctx := callerTokenContext("nobody", 999, []string{"superadmin"}, nil, "")
	_, err := api.CreateAuthToken(ctx, &adminv1.CreateAuthTokenRequest{ClientId: "c", ExpiresIn: 3600})
	assertStatusCode(t, err, 401)
}

// TestCreateAuthTokenNonSuperadminSubsetAllowed 验证非 superadmin 在自身能力子集内签发成功。
func TestCreateAuthTokenNonSuperadminSubsetAllowed(t *testing.T) {
	api := staticUserAPI()
	ctx := callerTokenContext(testStaticUsername, testStaticUserID, []string{"r1", "r2"}, []string{"g1"}, "acme")
	req := &adminv1.CreateAuthTokenRequest{
		ClientId:  "test-client",
		ExpiresIn: 3600,
		Tenant:    "acme",
		Roles:     []string{"r1"},
	}
	resp, err := api.CreateAuthToken(ctx, req)
	if err != nil {
		t.Fatalf("CreateAuthToken: %v", err)
	}
	var claims auth.AccessTokenClaims
	if _, err := jwt.ParseWithClaims(resp.AccessToken, &claims, func(*jwt.Token) (interface{}, error) {
		return []byte(testStaticPassword), nil
	}); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if !sameStrings(claims.Roles, []string{"r1"}) {
		t.Fatalf("roles = %v, want [r1]", claims.Roles)
	}
	if claims.Tenant != "acme" {
		t.Fatalf("tenant = %q, want acme", claims.Tenant)
	}
}

// TestCreateAuthTokenNonSuperadminRolesExceedScope 验证非 superadmin 越权签发返回 403。
func TestCreateAuthTokenNonSuperadminRolesExceedScope(t *testing.T) {
	api := staticUserAPI()
	ctx := callerTokenContext(testStaticUsername, testStaticUserID, []string{"r1"}, nil, "acme")
	_, err := api.CreateAuthToken(ctx, &adminv1.CreateAuthTokenRequest{
		ClientId:  "test-client",
		ExpiresIn: 3600,
		Roles:     []string{"r1", "r2"},
	})
	assertStatusCode(t, err, 403)
}
