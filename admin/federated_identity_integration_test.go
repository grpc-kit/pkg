package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestFederatedLoginAuthorizationContext(t *testing.T) {
	if federatedLoginAuthorizationFromContext(t.Context()) != nil {
		t.Fatal("普通 context 不应携带联邦授权")
	}
	authorization := FederatedLoginAuthorization{
		ClientID: "test-client", RedirectURI: "https://client.example.test/callback",
		Scope: "openid federated:id", ExpiresAt: time.Now().Add(time.Minute),
	}
	want := authorization
	ctx := ContextWithFederatedLoginAuthorization(t.Context(), authorization)
	authorization.Scope = ""
	got := federatedLoginAuthorizationFromContext(ctx)
	if got == nil || *got != want {
		t.Fatal("调用方修改参数影响了已注入的授权值")
	}
	got.ExpiresAt = time.Time{}
	if again := federatedLoginAuthorizationFromContext(ctx); again == nil || *again != want {
		t.Fatal("读取结果被修改后影响了 context 中的授权值")
	}
	if empty := federatedLoginAuthorizationFromContext(ContextWithFederatedLoginAuthorization(t.Context(), FederatedLoginAuthorization{})); empty == nil {
		t.Fatal("显式空授权不得视为普通登录，须交由入口拒绝")
	}
}

func verifiedFederatedTestToken(t *testing.T, api *KnownAdminAPI, raw string) *auth.AccessTokenClaims {
	t.Helper()
	key, _, err := loadAccessTokenRSAKey(t.Context(), api.config.db, api.config.aesKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := parsed.Claims.(jwt.MapClaims)["authorization_request_id"]; exists {
		t.Fatal("签发的 Access Token 仍包含私有授权流程字段")
	}
	claims := &auth.AccessTokenClaims{}
	if _, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired()); err != nil {
		t.Fatal(err)
	}
	return claims
}

func TestFederatedLoginIntegration(t *testing.T) {
	db := adminIntegrationClient(t)
	createTestLoginSigningKey(t, db)
	api := New(WithLionClient(db), WithAESKey([]byte(adminTestAESKey)), WithOIDCProvider("", "login-client", ""))
	t.Cleanup(func() { close(api.mfaChallenges.stopGC) })
	const both = "openid federated:id federated:username"
	client := db.OAuth2Clients.Create().SetClientID("federated-client").SetClientSecretHash("test-only").
		SetScopes([]string{"openid", auth.ScopeFederatedID, auth.ScopeFederatedUsername}).SetGrantTypes([]string{"authorization_code"}).
		SetRedirectUris([]string{"https://client.example.test/callback"}).SaveX(t.Context())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/token" {
			_ = r.ParseForm()
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": r.Form.Get("code"), "token_type": "Bearer"})
			return
		}
		info := map[string]string{"sub": "9007199254740993"}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer missing-username") {
			info["preferred_username"] = "Alice"
		}
		_ = json.NewEncoder(w).Encode(info)
	}))
	t.Cleanup(server.Close)
	provider := createTestAuthProvider(t, db, "company-ldap-via-oidc", adminv1.AuthProvider_OAUTH2)
	config, err := json.Marshal(oauthConfigData{ClientID: "upstream-client", AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token", UserinfoEndpoint: server.URL + "/userinfo", UserinfoNameField: "preferred_username"})
	if err != nil {
		t.Fatal(err)
	}
	provider.Update().SetConfig(config).SaveX(t.Context())
	request := FederatedLoginAuthorization{ClientID: client.ClientID, RedirectURI: client.RedirectUris[0], Scope: both, ExpiresAt: time.Now().Add(10 * time.Minute)}
	var last *auth.AccessTokenClaims
	for _, tc := range []struct{ scope, code string }{
		{"", "ordinary"}, {"openid federated:id", "id"}, {"openid federated:username", "username"},
		{both, "both"}, {"openid federated:username", "missing-username"}, {both, "missing-username-id"},
	} {
		t.Run(tc.code, func(t *testing.T) {
			req := &adminv1.GetAuthCallbackRequest{ProviderName: provider.Code, Code: tc.code}
			var result *adminv1.GetAuthCallbackResponse
			var err error
			if tc.scope == "" {
				// 公开 RPC 的 metadata 不能启用同进程专用授权能力。
				ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs(
					"scope", both, "client_id", client.ClientID))
				result, err = api.GetAuthCallback(ctx, req)
			} else {
				scoped := request
				scoped.Scope = tc.scope
				result, err = api.GetAuthCallback(ContextWithFederatedLoginAuthorization(t.Context(), scoped), req)
			}
			if err != nil {
				t.Fatal(err)
			}
			claims := verifiedFederatedTestToken(t, api, result.AccessToken)
			username := "Alice"
			if strings.HasPrefix(tc.code, "missing-username") {
				username = ""
			}
			want := auth.ProjectFederatedClaims(tc.scope, provider.Code, "9007199254740993", username)
			if !reflect.DeepEqual(want, claims.FederatedClaims) || canonicalScope(claims.Scope) != canonicalScope(tc.scope) {
				t.Fatalf("登录 Token 中 %s 对应的联邦字段不符合授权范围", tc.code)
			}
			expectedClient := client.ClientID
			if tc.scope == "" {
				expectedClient = "login-client"
			}
			if claims.ClientID != expectedClient {
				t.Fatal("登录改变了客户端绑定")
			}
			info, err := api.GetOAuth2Userinfo(rpc.ContextWithTokenClaims(t.Context(), claims), &emptypb.Empty{})
			if err != nil || info.GetSub() != claims.Subject || info.GetPreferredUsername() != claims.PreferredUsername {
				t.Fatalf("JWT 联邦资料改变了普通 UserInfo 身份：%v", err)
			}
			if tc.code == "both" {
				last = claims
			}
		})
	}
	t.Run("同进程授权边界", func(t *testing.T) {
		issuance, err := api.loginIssuanceContext(t.Context(), &request, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		original := request
		original.Scope = canonicalScope(original.Scope)
		changed := request
		copied, err := api.loginIssuanceContext(t.Context(), &changed, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		changed.Scope, changed.ExpiresAt = "", time.Now().Add(time.Hour)
		if *copied.authorization != original || copied.authorization == &changed || issuance.TTL != time.Hour {
			t.Fatal("已接受的授权参数被修改，或流程截止时间影响了 Token 有效期")
		}
		for _, tc := range []struct {
			name   string
			mutate func(*FederatedLoginAuthorization)
			code   codes.Code
		}{
			{"空授权不得退回普通登录", func(r *FederatedLoginAuthorization) { *r = FederatedLoginAuthorization{} }, codes.InvalidArgument},
			{"缺少openid", func(r *FederatedLoginAuthorization) { r.Scope = "federated:id" }, codes.InvalidArgument},
			{"未知授权范围", func(r *FederatedLoginAuthorization) { r.Scope = "openid federated:ids" }, codes.InvalidArgument},
			{"未允许的授权范围", func(r *FederatedLoginAuthorization) { r.Scope += " email" }, codes.PermissionDenied},
			{"未知客户端", func(r *FederatedLoginAuthorization) { r.ClientID = "other-client" }, codes.PermissionDenied},
			{"回调地址不匹配", func(r *FederatedLoginAuthorization) { r.RedirectURI = "https://other.example.test/callback" }, codes.PermissionDenied},
			{"缺少截止时间", func(r *FederatedLoginAuthorization) { r.ExpiresAt = time.Time{} }, codes.InvalidArgument},
			{"授权已过期", func(r *FederatedLoginAuthorization) { r.ExpiresAt = time.Now().Add(-time.Minute) }, codes.Unauthenticated},
		} {
			t.Run(tc.name, func(t *testing.T) {
				bad := request
				tc.mutate(&bad)
				if _, err := api.CreateAuthLogin(ContextWithFederatedLoginAuthorization(t.Context(), bad), &adminv1.CreateAuthLoginRequest{Username: "Alice", PasswordHash: "test-only"}); status.Code(err) != tc.code {
					t.Fatalf("密码登录未保留授权拒绝结果：%v", err)
				}
				if _, err := api.GetAuthCallback(ContextWithFederatedLoginAuthorization(t.Context(), bad), &adminv1.GetAuthCallbackRequest{ProviderName: provider.Code, Code: "test-only"}); status.Code(err) != tc.code {
					t.Fatalf("外部回调未保留授权拒绝结果：%v", err)
				}
			})
		}
		// 签发前复核当前权限，不能仅依赖入口检查。
		client.Update().SetGrantTypes([]string{"refresh_token"}).SaveX(t.Context())
		if err := api.applyFederatedLoginClaims(t.Context(), last, issuance); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("最终签发未拒绝已撤回的授权类型：%v", err)
		}
		client.Update().SetGrantTypes(client.GrantTypes).SaveX(t.Context())
		client.Update().SetClientStatus(int(adminv1.OAuth2Client_DISABLED)).SaveX(t.Context())
		if err := api.applyFederatedLoginClaims(t.Context(), last, issuance); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("最终签发未拒绝已禁用的客户端：%v", err)
		}
		client.Update().SetClientStatus(client.ClientStatus).SaveX(t.Context())
	})
	t.Run("本地静态登录不构造外部来源", func(t *testing.T) {
		static := &StaticUsers{&StaticUser{Username: "local-test", PasswordHash: strings.Repeat("1", 64)}}
		localAPI := New(WithLionClient(db), WithAESKey([]byte(adminTestAESKey)), WithOIDCProvider("", "login-client", ""), WithStaticUsers(static))
		t.Cleanup(func() { close(localAPI.mfaChallenges.stopGC) })
		result, err := localAPI.CreateAuthLogin(ContextWithFederatedLoginAuthorization(t.Context(), request), &adminv1.CreateAuthLoginRequest{Username: "local-test", PasswordHash: strings.Repeat("1", 64)})
		if err != nil {
			t.Fatal(err)
		}
		claims := &auth.AccessTokenClaims{}
		if _, err := jwt.ParseWithClaims(result.AccessToken, claims, func(*jwt.Token) (any, error) { return []byte(strings.Repeat("1", 64)), nil }, jwt.WithValidMethods([]string{"HS256"})); err != nil {
			t.Fatal(err)
		}
		parsed, _, err := jwt.NewParser().ParseUnverified(result.AccessToken, jwt.MapClaims{})
		if err != nil {
			t.Fatal(err)
		}
		if _, exists := parsed.Claims.(jwt.MapClaims)["authorization_request_id"]; exists {
			t.Fatal("静态登录 Token 仍包含私有授权流程字段")
		}
		if claims.FederatedClaims != nil || claims.ClientID != client.ClientID {
			t.Fatal("静态登录构造了外部来源或改变了客户端绑定")
		}
	})
	t.Run("最终登录门禁保留授权拒绝结果", func(t *testing.T) {
		issuance, err := api.loginIssuanceContext(t.Context(), &request, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		issuance.authorization.ExpiresAt = time.Now().Add(-time.Second)
		userID, err := strconv.Atoi(last.Subject)
		if err != nil {
			t.Fatal(err)
		}
		result, err := api.applyMFAGateAfterPrimaryAuth(t.Context(), db, userID, last.PreferredUsername, false, "hidden-fallback-token", issuance, provider.ID)
		if status.Code(err) != codes.Unauthenticated || result.GetAccessToken() != "" {
			t.Fatalf("最终登录门禁覆盖了拒绝结果或返回了备用 Token：%v", err)
		}
	})
	t.Run("客户端撤权后拒绝新的联邦签发", func(t *testing.T) {
		issuance, err := api.loginIssuanceContext(t.Context(), &request, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		// 使用后台页面实际提交的 FieldMask JSON 清空最后一个 scope，
		// 重读确认已保存，再验证入口与最终签发均拒绝已撤回的范围。
		body, err := json.Marshal(map[string]any{
			"id":          client.ID,
			"update_mask": "displayName,clientStatus,redirectUris,grantTypes,scopes,logoUrl,description",
			"client": map[string]any{
				"display_name": "regression-client", "client_status": client.ClientStatus,
				"redirect_uris": client.RedirectUris, "grant_types": client.GrantTypes,
				"scopes": []string{}, "logo_url": "", "description": "",
			},
			"client_secret": "",
		})
		if err != nil {
			t.Fatal(err)
		}
		update := &adminv1.UpdateOAuth2ClientRequest{}
		if err := protojson.Unmarshal(body, update); err != nil {
			t.Fatal(err)
		}
		if _, err := api.UpdateOAuth2Client(t.Context(), update); err != nil {
			t.Fatal(err)
		}
		stored, err := api.GetOAuth2Client(t.Context(), &adminv1.GetOAuth2ClientRequest{Id: int64(client.ID)})
		if err != nil || len(stored.GetScopes()) != 0 || int(stored.GetClientStatus()) != client.ClientStatus || len(stored.GetRedirectUris()) != len(client.RedirectUris) {
			t.Fatalf("清空授权范围未保存或意外修改其他客户端字段：%v", err)
		}
		if db.OAuth2Clients.GetX(t.Context(), client.ID).ClientSecretHash != client.ClientSecretHash {
			t.Fatal("普通客户端编辑不应轮换密钥")
		}
		if _, err := api.GetAuthCallback(ContextWithFederatedLoginAuthorization(t.Context(), request), &adminv1.GetAuthCallbackRequest{ProviderName: provider.Code, Code: "revoked"}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("客户端撤权后新的联邦登录未被拒绝：%v", err)
		}
		if err := api.applyFederatedLoginClaims(t.Context(), last, issuance); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("最终签发未复核客户端撤权：%v", err)
		}
	})
}
