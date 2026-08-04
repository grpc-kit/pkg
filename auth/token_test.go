package auth

import (
	"testing"

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
