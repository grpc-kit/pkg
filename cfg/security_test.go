package cfg

import (
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/crypto"
)

func TestSecurity(t *testing.T) {
	t.Run("testSecurityConfig", testSecurityConfig)
	t.Run("testSecurityTokenHS256", testSecurityTokenHS256)
}

func TestVerifyBearerTokenRS256WithoutIssuerAudience(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	claims := &auth.AccessTokenClaims{
		CommonClaims: auth.CommonClaims{RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "42",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}},
		ClientID: "unverified-client",
	}
	tokenString, err := auth.SignAccessTokenRSA(claims, privateKey, "test-key")
	if err != nil {
		t.Fatal(err)
	}
	security := &SecurityConfig{}
	security.setVerifier(oidc.NewVerifier(
		"https://key-provider.example.com",
		&oidc.StaticKeySet{PublicKeys: []stdcrypto.PublicKey{&privateKey.PublicKey}},
		&oidc.Config{SkipIssuerCheck: true, SkipClientIDCheck: true},
	))
	verified, err := security.verifyBearerToken(context.Background(), tokenString)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Subject != "42" || verified.Issuer != "" || len(verified.Audience) != 0 {
		t.Fatalf("claims mismatch: %+v", verified)
	}
}

func testSecurityConfig(t *testing.T) {
	if lc == nil || lc.Security == nil {
		t.Fatal("LocalConfig or SecurityConfig not initialized; run TestConfig first")
	}
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
	const testUserPassword = "test-password-123"
	testUserID := crypto.Username2UserID("testuser")

	buildHS256SecurityConfig := func(skipExpiry, skipIssuer, skipClientID bool) *SecurityConfig {
		return &SecurityConfig{
			Enable: true,
			Authentication: &Authentication{
				OIDCProvider: &OIDCProvider{
					Issuer: "https://key-provider.example.com",
					Config: &OIDCConfig{
						SupportedSigningAlgs: []string{"HS256"},
						SkipExpiryCheck:      skipExpiry,
						SkipIssuerCheck:      skipIssuer,
						SkipClientIDCheck:    skipClientID,
						ClientID:             "expected-client",
					},
				},
				HTTPUsers: []*BasicAuth{{
					UserID:   testUserID,
					Username: "testuser",
					Password: testUserPassword,
				}},
			},
		}
	}

	makeClaims := func() *auth.AccessTokenClaims {
		return &auth.AccessTokenClaims{
			CommonClaims: auth.CommonClaims{RegisteredClaims: jwt.RegisteredClaims{
				Subject:   "testuser",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
			}},
			ClientID: "unverified-client",
			Scope:    "openid profile",
		}
	}

	sign := func(claims jwt.Claims, password string) string {
		t.Helper()
		tokenString, err := auth.SignAccessToken(claims, password)
		if err != nil {
			t.Fatal(err)
		}
		return tokenString
	}

	ctx := context.Background()

	t.Run("ValidTokenWithoutIssuerOrAudience", func(t *testing.T) {
		claims, err := buildHS256SecurityConfig(false, true, true).verifyBearerToken(ctx, sign(makeClaims(), testUserPassword))
		if err != nil {
			t.Fatal(err)
		}
		if claims.Subject != "testuser" || claims.ClientID != "unverified-client" {
			t.Fatalf("claims mismatch: %+v", claims)
		}
		if claims.Issuer != "" || len(claims.Audience) != 0 {
			t.Fatalf("issuer/audience must not be required: iss=%q aud=%v", claims.Issuer, claims.Audience)
		}
	})

	t.Run("IssuerAudienceAndClientIDAreNotCheckedWhenConfigured", func(t *testing.T) {
		claims := makeClaims()
		claims.Issuer = "https://unrelated.example.com"
		claims.Audience = []string{"unrelated-resource"}
		claims.ClientID = "unrelated-client"
		if _, err := buildHS256SecurityConfig(false, true, true).verifyBearerToken(ctx, sign(claims, testUserPassword)); err != nil {
			t.Fatalf("optional claims must not affect verification: %v", err)
		}
	})

	t.Run("IssuerCheckFollowsConfig", func(t *testing.T) {
		_, err := buildHS256SecurityConfig(false, false, true).verifyBearerToken(ctx, sign(makeClaims(), testUserPassword))
		if !errors.Is(err, jwt.ErrTokenInvalidIssuer) {
			t.Fatalf("expected ErrTokenInvalidIssuer, got %v", err)
		}
	})

	t.Run("ClientIDCheckFollowsConfig", func(t *testing.T) {
		claims := makeClaims()
		claims.Issuer = "https://key-provider.example.com"
		_, err := buildHS256SecurityConfig(false, false, false).verifyBearerToken(ctx, sign(claims, testUserPassword))
		if !errors.Is(err, jwt.ErrTokenInvalidAudience) {
			t.Fatalf("expected ErrTokenInvalidAudience, got %v", err)
		}
		claims.Audience = []string{"expected-client"}
		if _, err := buildHS256SecurityConfig(false, false, false).verifyBearerToken(ctx, sign(claims, testUserPassword)); err != nil {
			t.Fatalf("configured issuer/audience should pass: %v", err)
		}
	})

	t.Run("InvalidToken", func(t *testing.T) {
		if _, err := buildHS256SecurityConfig(false, true, true).verifyBearerToken(ctx, "not.a.valid.token"); err == nil {
			t.Fatal("expected invalid token error")
		}
	})

	t.Run("WrongSigningKey", func(t *testing.T) {
		if _, err := buildHS256SecurityConfig(false, true, true).verifyBearerToken(ctx, sign(makeClaims(), "wrong-password")); err == nil {
			t.Fatal("expected signature error")
		}
	})

	t.Run("ExpiredTokenNotSkipped", func(t *testing.T) {
		claims := makeClaims()
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
		_, err := buildHS256SecurityConfig(false, true, true).verifyBearerToken(ctx, sign(claims, testUserPassword))
		if !errors.Is(err, jwt.ErrTokenExpired) {
			t.Fatalf("expected ErrTokenExpired, got %v", err)
		}
	})

	t.Run("ExpiredTokenSkipped", func(t *testing.T) {
		claims := makeClaims()
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
		if _, err := buildHS256SecurityConfig(true, true, true).verifyBearerToken(ctx, sign(claims, testUserPassword)); err != nil {
			t.Fatalf("skip expiry token failed: %v", err)
		}
	})

	t.Run("SkipExpiryStillChecksIssuerAndAudience", func(t *testing.T) {
		claims := makeClaims()
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))

		_, err := buildHS256SecurityConfig(true, false, true).verifyBearerToken(ctx, sign(claims, testUserPassword))
		if !errors.Is(err, jwt.ErrTokenInvalidIssuer) {
			t.Fatalf("expected ErrTokenInvalidIssuer, got %v", err)
		}

		claims.Issuer = "https://key-provider.example.com"
		_, err = buildHS256SecurityConfig(true, false, false).verifyBearerToken(ctx, sign(claims, testUserPassword))
		if !errors.Is(err, jwt.ErrTokenInvalidAudience) {
			t.Fatalf("expected ErrTokenInvalidAudience, got %v", err)
		}
	})

	t.Run("SkipExpiryStillVerifiesSignature", func(t *testing.T) {
		claims := makeClaims()
		claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
		if _, err := buildHS256SecurityConfig(true, true, true).verifyBearerToken(ctx, sign(claims, "wrong-password")); err == nil {
			t.Fatal("skip expiry must not skip signature verification")
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
