package auth

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-kit/pkg/crypto"
)

// TestAccessTokenClaims_PromotedMethodsAndSigning 验证重构后的两个关键性质：
//  1. AccessTokenClaims 经嵌入提升获得 CommonClaims 的 setter 与 GetMustUserID；
//  2. 签名时按具体类型完整序列化，保留 Access Token 专有声明（client_id/scope），
//     而非仅序列化 CommonClaims。
func TestAccessTokenClaims_PromotedMethodsAndSigning(t *testing.T) {
	const signKey = "test-sign-key"

	at := &AccessTokenClaims{}
	at.ClientID = "test-client-id"
	at.Scope = "openid profile"

	// 提升自 CommonClaims 的 setter
	at.SetSubject("123")
	at.SetGroups([]string{"superadmin"})
	at.SetRoles([]string{"admin"})
	at.SetExpiresAt(3600)
	at.SetEmail("user@example.com")

	// GetMustUserID 同样经提升可用
	if got := at.GetMustUserID(); got != 123 {
		t.Fatalf("GetMustUserID = %d, want 123", got)
	}

	tok, err := at.GetAccessToken(signKey)
	if err != nil {
		t.Fatalf("GetAccessToken: %v", err)
	}

	// 解码（不校验签名）验证具体类型被完整序列化
	var decoded AccessTokenClaims
	if _, _, err := jwt.NewParser().ParseUnverified(tok, &decoded); err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}

	if decoded.Subject != "123" {
		t.Errorf("Subject = %q, want 123", decoded.Subject)
	}
	if len(decoded.Groups) != 1 || decoded.Groups[0] != "superadmin" {
		t.Errorf("Groups = %v, want [superadmin]", decoded.Groups)
	}
	if len(decoded.Roles) != 1 || decoded.Roles[0] != "admin" {
		t.Errorf("Roles = %v, want [admin]", decoded.Roles)
	}
	if decoded.Email != "user@example.com" {
		t.Errorf("Email = %q, want user@example.com", decoded.Email)
	}
	if decoded.ExpiresAt == nil {
		t.Error("ExpiresAt = nil, want set")
	}

	// Access Token 专有声明必须保留（证明未退化为仅序列化 CommonClaims）
	if decoded.ClientID != "test-client-id" {
		t.Errorf("ClientID = %q, want test-client-id", decoded.ClientID)
	}
	if decoded.Scope != "openid profile" {
		t.Errorf("Scope = %q, want openid profile", decoded.Scope)
	}

	headerOnly, _, err := jwt.NewParser().ParseUnverified(tok, &AccessTokenClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified header: %v", err)
	}
	if got := headerOnly.Header["typ"]; got != "at+jwt" {
		t.Fatalf("Access Token typ = %v, want at+jwt", got)
	}
}

func TestIDTokenHeaderType(t *testing.T) {
	tok, err := (&IDTokenClaims{}).GetAccessToken("test-sign-key")
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := jwt.NewParser().ParseUnverified(tok, &IDTokenClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if got := token.Header["typ"]; got != "JWT" {
		t.Fatalf("ID Token typ = %v, want JWT", got)
	}
}

func TestPreferredUsernameCompatibility(t *testing.T) {
	tests := []struct {
		name       string
		claims     CommonClaims
		want       string
		wantUserID int64
	}{
		{name: "standard claim", claims: CommonClaims{PreferredUsername: "preferred"}, want: "preferred", wantUserID: crypto.Username2UserID("preferred")},
		{name: "legacy claim", claims: CommonClaims{Username: "legacy"}, want: "legacy", wantUserID: crypto.Username2UserID("legacy")},
		{name: "standard wins", claims: CommonClaims{PreferredUsername: "preferred", Username: "legacy"}, want: "preferred", wantUserID: crypto.Username2UserID("preferred")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := tt.claims
			if got := claims.GetPreferredUsername(); got != tt.want {
				t.Fatalf("GetPreferredUsername() = %q, want %q", got, tt.want)
			}
			claims.Subject = "not-a-number"
			if got := claims.GetMustUserID(); got != tt.wantUserID {
				t.Fatalf("GetMustUserID() = %d, want %d", got, tt.wantUserID)
			}
		})
	}
}

func TestSignedGroupsOnlyTokenDoesNotGrantRoles(t *testing.T) {
	claims := &AccessTokenClaims{CommonClaims: CommonClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Groups: []string{"admin"},
	}}
	tokenString, err := claims.GetAccessToken("test-key")
	if err != nil {
		t.Fatal(err)
	}
	var decoded AccessTokenClaims
	if _, _, err := jwt.NewParser().ParseUnverified(tokenString, &decoded); err != nil {
		t.Fatal(err)
	}
	if roles := EffectiveRoles(decoded); len(roles) != 0 {
		t.Fatalf("groups-only token granted roles: %v", roles)
	}
}

func TestSetEmailDoesNotSynthesizeOrVerifyMissingEmail(t *testing.T) {
	claims := &AccessTokenClaims{}
	claims.SetSubject("42")
	claims.EmailVerified = true
	claims.SetEmail("")
	if claims.Email != "" || claims.EmailVerified {
		t.Fatalf("missing email was synthesized or verified: email=%q verified=%t", claims.Email, claims.EmailVerified)
	}
	claims.SetEmail(" user@example.com ")
	claims.EmailVerified = true
	if claims.Email != "user@example.com" || !claims.EmailVerified {
		t.Fatalf("real email was not preserved: email=%q verified=%t", claims.Email, claims.EmailVerified)
	}
}

func TestLegacyAppidStillParses(t *testing.T) {
	claims := &AccessTokenClaims{CommonClaims: CommonClaims{Appid: "legacy-app"}}
	tokenString, err := claims.GetAccessToken("test-key")
	if err != nil {
		t.Fatal(err)
	}
	var decoded AccessTokenClaims
	if _, _, err := jwt.NewParser().ParseUnverified(tokenString, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Appid != "legacy-app" {
		t.Fatalf("legacy appid = %q", decoded.Appid)
	}
}

func TestFederatedProjection(t *testing.T) {
	userID, username := "9007199254740993", "Alice"
	for _, tc := range []struct {
		scope, username string
		want            *FederatedClaims
		wantJSON        string
	}{
		{"openid", username, nil, `{}`},
		{"openid federated:ids federated:username:extra", username, nil, `{}`},
		{"openid federated:id", username, &FederatedClaims{ConnectorID: "ldap", UserID: &userID}, `{"federated_claims":{"connector_id":"ldap","user_id":"9007199254740993"}}`},
		{"openid federated:username", username, &FederatedClaims{ConnectorID: "ldap", Username: &username}, `{"federated_claims":{"connector_id":"ldap","username":"Alice"}}`},
		{"openid federated:id federated:username", username, &FederatedClaims{ConnectorID: "ldap", UserID: &userID, Username: &username}, `{"federated_claims":{"connector_id":"ldap","user_id":"9007199254740993","username":"Alice"}}`},
		{"openid federated:username", "", nil, `{}`},
		{"openid federated:id federated:username", "", &FederatedClaims{ConnectorID: "ldap", UserID: &userID}, `{"federated_claims":{"connector_id":"ldap","user_id":"9007199254740993"}}`},
	} {
		t.Run(tc.scope+"/"+tc.username, func(t *testing.T) {
			got := ProjectFederatedClaims(tc.scope, "ldap", userID, tc.username)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("实际投影为 %v，预期为 %v", got, tc.want)
			}
			data, err := json.Marshal(CommonClaims{FederatedClaims: got})
			if err != nil || string(data) != tc.wantJSON {
				t.Fatalf("JWT JSON 与 scope 契约不符：%s，%v", data, err)
			}
			var parsed CommonClaims
			if err := json.Unmarshal([]byte(tc.wantJSON), &parsed); err != nil || !reflect.DeepEqual(parsed.FederatedClaims, tc.want) {
				t.Fatalf("约定 JSON 无法还原为相同资料：%v", err)
			}
		})
	}
	for _, value := range []string{"", " Alice", "Alice ", "a\nb", "a\x00b", string([]byte{0xff}), strings.Repeat("a", 256)} {
		if ValidFederatedUsername(value) || ProjectFederatedClaims(ScopeFederatedUsername, "ldap", "id", value) != nil {
			t.Errorf("输出了不合法的外部用户名：%q", value)
		}
	}
	if !ValidFederatedUsername("用户.Alice") || ProjectFederatedClaims(ScopeFederatedID, "", "id", username) != nil {
		t.Fatal("空来源或合法 Unicode 用户名的处理不符合预期")
	}
}

func TestFederatedSnapshot(t *testing.T) {
	username := "Alice"
	usernameOnly := &FederatedClaims{ConnectorID: "ldap", Username: &username}
	if !ValidFederatedClaims("openid federated:username", usernameOnly) || !reflect.DeepEqual(ProjectFederatedSnapshot(ScopeFederatedUsername, usernameOnly), usernameOnly) {
		t.Fatal("仅含用户名的快照不应要求未授权的 user_id")
	}
	if ProjectFederatedSnapshot(ScopeFederatedID, usernameOnly) != nil {
		t.Fatal("用户名授权不应生成外部 ID")
	}
	// 通过真实 JSON 解码覆盖未知键、错误类型、空值及越权字段，避免结构体静默丢弃输入。
	for _, tc := range []struct{ scope, raw string }{
		{"openid federated:username", `{"connector_id":"ldap"}`},
		{"openid federated:username", `{"connector_id":"ldap","username":" Alice"}`},
		{"openid federated:username", `{"connector_id":"ldap","username":"Alice","user_id":"ungranted"}`},
		{"openid federated:username", `{"connector_id":"ldap","username":"Alice","other":"extra"}`},
		{"openid federated:username", `{"connector_id":"ldap","Username":"Alice"}`},
		{"openid federated:username", `{"connector_id":"ldap","username":"Alice","Username":"other"}`},
		{"openid federated:username", `{"username":"Alice"}`},
		{"openid federated:id", `{"connector_id":"ldap","user_id":""}`},
		{"openid federated:id", `{"connector_id":"ldap","user_id":9007199254740993}`},
		{"openid federated:id federated:username", `{"connector_id":"ldap","user_id":"id","username":null}`},
		{"openid federated:username", `{"connector_id":"ldap","username":null}`},
		{"openid federated:username", `{}`},
		{"openid federated:username", `[]`},
	} {
		var claims CommonClaims
		err := json.Unmarshal([]byte(`{"federated_claims":`+tc.raw+`}`), &claims)
		if err == nil && ValidFederatedClaims(tc.scope, claims.FederatedClaims) {
			t.Fatalf("接受了格式错误或超出授权范围的快照：%s", tc.raw)
		}
	}
	projected := ProjectFederatedSnapshot(ScopeFederatedUsername, usernameOnly)
	*projected.Username = "changed"
	if *usernameOnly.Username != "Alice" || !ValidFederatedClaims("openid federated:username", nil) || ValidFederatedClaims("openid", usernameOnly) {
		t.Fatal("快照副本、缺失来源或授权范围的处理不符合预期")
	}
	var ordinary CommonClaims
	if err := json.Unmarshal([]byte(`{"extra":"allowed","federated_claims":null}`), &ordinary); err != nil || ordinary.FederatedClaims != nil {
		t.Fatalf("普通声明扩展或 null 外部来源的兼容行为发生变化：%v", err)
	}
	if err := json.Unmarshal([]byte(`{"federated_claims":{"connector_id":"ldap","username":"Alice","tenant_id":"org-a"}}`), &ordinary); err != nil {
		t.Fatalf("上游字符串扩展不应在公共解码时被拒绝：%v", err)
	}
	if ValidFederatedClaims("openid federated:username", ordinary.FederatedClaims) || ProjectFederatedSnapshot(ScopeFederatedUsername, ordinary.FederatedClaims) != nil {
		t.Fatal("未知字段通过联邦校验或投影后被静默接受")
	}
}
