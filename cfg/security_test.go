package cfg

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/crypto"
)

func TestSecurity(t *testing.T) {
	t.Run("testSecurityConfig", testSecurityConfig)
	t.Run("testSecurityTokenHS256", testSecurityTokenHS256)
}

func testSecurityConfig(t *testing.T) {
	if !lc.Security.Enable {
		t.Errorf("security.enable not true")
	}
	if lc.Security.Authentication == nil {
		t.Errorf("security.authentication is nil")
	}
	if lc.Security.Authorization == nil {
		t.Errorf("security.authorization is nil")
	}
}

func testSecurityTokenHS256(t *testing.T) {
	const (
		testUserPassword = "test-password-123"
		testIssuer       = "https://test-issuer.local"
		testClientID     = "test-client-id"
	)
	// Username2UserID("testuser") produces a deterministic int64
	testUserID := crypto.Username2UserID("testuser")

	// buildHS256SecurityConfig constructs a SecurityConfig wired for HS256 with
	// configurable SkipExpiry/SkipIssuer/SkipClientID flags and a single HTTP user.
	buildHS256SecurityConfig := func(skipExpiry, skipIssuer, skipClientID bool) *SecurityConfig {
		return &SecurityConfig{
			Enable: true,
			Authentication: &Authentication{
				OIDCProvider: &OIDCProvider{
					Issuer: testIssuer,
					Config: &OIDCConfig{
						ClientID:             testClientID,
						SupportedSigningAlgs: []string{"HS256"},
						SkipExpiryCheck:      skipExpiry,
						SkipIssuerCheck:      skipIssuer,
						SkipClientIDCheck:    skipClientID,
					},
				},
				HTTPUsers: []*BasicAuth{
					{
						UserID:   testUserID,
						Username: "testuser",
						Password: testUserPassword,
					},
				},
			},
		}
	}

	// signHS256Token creates a valid HS256 token signed with SHA256(password).
	signHS256Token := func(s *SecurityConfig, claims *auth.IDTokenClaims) string {
		t.Helper()
		tokenStr, err := claims.GetAccessToken(testUserPassword)
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		return tokenStr
	}

	// makeValidClaims returns claims that should pass all checks.
	makeValidClaims := func() *auth.IDTokenClaims {
		return &auth.IDTokenClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "testuser",
				Issuer:    testIssuer,
				Audience:  []string{testClientID},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			},
			Email: "testuser@localhost",
		}
	}

	ctx := context.Background()

	// --- 有效 token + 正确 audience -> 通过 ---
	t.Run("ValidToken", func(t *testing.T) {
		s := buildHS256SecurityConfig(false, false, false)
		tokenStr := signHS256Token(s, makeValidClaims())
		claims, err := s.verifyBearerToken(ctx, tokenStr)
		if err != nil {
			t.Fatalf("expected nil error for valid token, got: %v", err)
		}
		if claims.Subject != "testuser" {
			t.Errorf("expected subject 'testuser', got %q", claims.Subject)
		}
	})

	// --- 非法 token ---
	t.Run("InvalidToken", func(t *testing.T) {
		s := buildHS256SecurityConfig(false, false, false)
		_, err := s.verifyBearerToken(ctx, "not.a.valid.token")
		if err == nil {
			t.Fatalf("expected error for invalid token, got nil")
		}
	})

	// --- 有效 token，但签名密钥不对 ---
	t.Run("WrongSigningKey", func(t *testing.T) {
		s := buildHS256SecurityConfig(false, false, false)
		// 用不同密钥签发 token
		claims := makeValidClaims()
		_, err := claims.GetAccessToken("wrong-password")
		if err != nil {
			t.Fatalf("failed to sign token: %v", err)
		}
		// 但这里用 wrong-password 签出来的 key = SHA256("wrong-password")
		// 而 hs256Verify 会用 SHA256(testUserPassword)，所以验签失败
		wrongKey := crypto.SHA256([]byte("wrong-password"))
		tokenStr, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(wrongKey))
		_, err = s.verifyBearerToken(ctx, tokenStr)
		if err == nil {
			t.Fatalf("expected error for wrong signing key, got nil")
		}
	})

	// --- 有效 token，但时间过期，必须验证时间 ---
	// v4/v5 行为：过期 + SkipExpiryCheck=false 时，switch 匹配 ErrTokenExpired 但不 return，
	// 继续走到 token.Valid==false 检查，最终返回 ErrInvalidKey
	t.Run("ExpiredToken_NotSkipped", func(t *testing.T) {
		s := buildHS256SecurityConfig(false, false, false)
		claims := makeValidClaims()
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Hour))
		tokenStr := signHS256Token(s, claims)
		_, err := s.verifyBearerToken(ctx, tokenStr)
		if err == nil {
			t.Fatalf("expected error for expired token, got nil")
		}
		if !errors.Is(err, jwt.ErrInvalidKey) {
			t.Errorf("expected ErrInvalidKey for expired token without SkipExpiryCheck, got: %v", err)
		}
	})

	// --- 有效 token，但时间过期，忽略时间验证 ---
	t.Run("ExpiredToken_SkippedExpiry", func(t *testing.T) {
		s := buildHS256SecurityConfig(true, false, false)
		claims := makeValidClaims()
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Hour))
		tokenStr := signHS256Token(s, claims)
		_, err := s.verifyBearerToken(ctx, tokenStr)
		if err != nil {
			t.Fatalf("expected nil error for expired token with SkipExpiryCheck=true, got: %v", err)
		}
	})

	// --- 有效 token，时间未过期，但 client_id 不匹配 ---
	t.Run("WrongAudience", func(t *testing.T) {
		s := buildHS256SecurityConfig(false, false, false)
		claims := makeValidClaims()
		claims.Audience = []string{"wrong-client-id"}
		tokenStr := signHS256Token(s, claims)
		_, err := s.verifyBearerToken(ctx, tokenStr)
		if err == nil {
			t.Fatalf("expected error for wrong audience, got nil")
		}
		if !errors.Is(err, jwt.ErrTokenInvalidAudience) {
			t.Errorf("expected ErrTokenInvalidAudience, got: %v", err)
		}
	})

	// --- 有效 token，时间未过期，但 issuer 不匹配 ---
	t.Run("WrongIssuer", func(t *testing.T) {
		s := buildHS256SecurityConfig(false, false, false)
		claims := makeValidClaims()
		claims.Issuer = "https://wrong-issuer.local"
		tokenStr := signHS256Token(s, claims)
		_, err := s.verifyBearerToken(ctx, tokenStr)
		if err == nil {
			t.Fatalf("expected error for wrong issuer, got nil")
		}
		if !errors.Is(err, jwt.ErrTokenInvalidIssuer) {
			t.Errorf("expected ErrTokenInvalidIssuer, got: %v", err)
		}
	})

	// --- 过期 token + SkipExpiryCheck=true + 错误 audience -> 返回 nil（v4 行为保持）---
	// v4/v5 方案 B 行为：过期 + SkipExpiryCheck=true 时，代码在 err 处理阶段直接 return nil，
	// 不会到达后续的 audience 手动校验。这是 v4 原有行为，升级后精确保持一致。
	t.Run("ExpiredAndWrongAudience_SkipExpiryCheck", func(t *testing.T) {
		s := buildHS256SecurityConfig(true, false, false)
		claims := makeValidClaims()
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-1 * time.Hour))
		claims.Audience = []string{"wrong-client-id"}
		tokenStr := signHS256Token(s, claims)
		_, err := s.verifyBearerToken(ctx, tokenStr)
		// v4 行为：SkipExpiryCheck=true 时过期 token 直接通过，audience 不校验
		if err != nil {
			t.Errorf("expected nil for expired+wrong-audience token with SkipExpiryCheck=true (v4 behavior preserved), got: %v", err)
		}
	})
}

// --- VerifyHTTPRequest 测试 ---

func TestVerifyHTTPRequest(t *testing.T) {
	// 确保 lc 已初始化（依赖 TestConfig 先执行）
	if lc == nil || lc.Security == nil {
		t.Skip("LocalConfig or SecurityConfig not initialized; run TestConfig first")
	}

	t.Run("Disabled", func(t *testing.T) {
		s := &SecurityConfig{Enable: false}
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		if err := s.VerifyHTTPRequest(req); err != nil {
			t.Fatalf("expected nil for disabled security, got: %v", err)
		}
	})

	t.Run("NilSecurity", func(t *testing.T) {
		var s *SecurityConfig
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		if err := s.VerifyHTTPRequest(req); err != nil {
			t.Fatalf("expected nil for nil security, got: %v", err)
		}
	})

	t.Run("BasicAuth_NoHeader", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		err := lc.Security.VerifyHTTPRequest(req)
		if err == nil {
			t.Fatalf("expected error for missing Authorization header, got nil")
		}
	})

	t.Run("BasicAuth_Valid", func(t *testing.T) {
		// app-sample.yaml 中配置了 user1:pass1
		cred := base64.StdEncoding.EncodeToString([]byte("user1:pass1"))
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.Header.Set("Authorization", "Basic "+cred)
		err := lc.Security.VerifyHTTPRequest(req)
		if err != nil {
			t.Fatalf("expected nil for valid basic auth, got: %v", err)
		}
	})

	t.Run("BasicAuth_InvalidPassword", func(t *testing.T) {
		cred := base64.StdEncoding.EncodeToString([]byte("user1:wrongpass"))
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.Header.Set("Authorization", "Basic "+cred)
		err := lc.Security.VerifyHTTPRequest(req)
		if err == nil {
			t.Fatalf("expected error for invalid password, got nil")
		}
	})

	t.Run("BasicAuth_UnknownUser", func(t *testing.T) {
		cred := base64.StdEncoding.EncodeToString([]byte("unknown:pass"))
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.Header.Set("Authorization", "Basic "+cred)
		err := lc.Security.VerifyHTTPRequest(req)
		if err == nil {
			t.Fatalf("expected error for unknown user, got nil")
		}
	})

	t.Run("BasicAuth_InvalidEncoding", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.Header.Set("Authorization", "Basic !!!not-base64!!!")
		err := lc.Security.VerifyHTTPRequest(req)
		if err == nil {
			t.Fatalf("expected error for invalid base64, got nil")
		}
	})

	t.Run("BearerToken_Empty", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer ")
		err := lc.Security.VerifyHTTPRequest(req)
		if err == nil {
			t.Fatalf("expected error for empty bearer token, got nil")
		}
	})

	t.Run("BearerToken_Invalid", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		err := lc.Security.VerifyHTTPRequest(req)
		if err == nil {
			t.Fatalf("expected error for invalid bearer token, got nil")
		}
	})
}
