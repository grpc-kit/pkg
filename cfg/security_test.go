package cfg

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurity(t *testing.T) {
	t.Run("testSecurityConfig", testSecurityConfig)
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
	// 有效 token

	// 非法 token

	// 有效 token，但签名密钥不对

	// 有效 token，但时间过期，必须验证时间

	// 有效 token，但时间过期，忽略时间验证

	// 有效 token, 时间未过期，但 client_id 不匹配

	// 有效 token, 时间未过期，但 issuer 不匹配
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
