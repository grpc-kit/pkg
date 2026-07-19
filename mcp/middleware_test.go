package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// dummyHandler 返回 200 OK 并标记已调用
func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
}

func TestAuthMiddleware_NoAuth(t *testing.T) {
	// authFn == nil 时应直接放行
	h := NewAuthMiddleware(nil, dummyHandler())
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestAuthMiddleware_NoHeader(t *testing.T) {
	// 有 authFn 但请求无 Authorization header -> 401
	authFn := func(r *http.Request) error {
		if r.Header.Get("Authorization") == "" {
			return errUnauthorized("missing Authorization header")
		}
		return nil
	}
	h := NewAuthMiddleware(authFn, dummyHandler())
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse error body: %v", err)
	}
	if body["error"] == "" {
		t.Fatalf("error field is empty in response body")
	}
}

func TestAuthMiddleware_ValidBasic(t *testing.T) {
	// authFn 返回 nil（模拟验证通过）-> 200
	authFn := func(r *http.Request) error {
		return nil // 模拟验证通过
	}
	h := NewAuthMiddleware(authFn, dummyHandler())
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz") // user:pass
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestAuthMiddleware_InvalidBearer(t *testing.T) {
	// authFn 返回 error -> 401
	authFn := func(r *http.Request) error {
		return errUnauthorized("invalid bearer token")
	}
	h := NewAuthMiddleware(authFn, dummyHandler())
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse error body: %v", err)
	}
	if body["error"] != "invalid bearer token" {
		t.Fatalf("unexpected error message: %q", body["error"])
	}
}

func TestLoggingMiddleware(t *testing.T) {
	// LoggingMiddleware 不影响请求处理
	h := LoggingMiddleware(dummyHandler())
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

// captureAuthHandler 捕获下游收到的 context 中的 Authorization 值。
type captureAuthHandler struct {
	got string
}

func (c *captureAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.got = AuthHeaderFromContext(r.Context())
	w.WriteHeader(http.StatusOK)
}

func TestAuthMiddleware_InjectsAuthHeader(t *testing.T) {
	// 设置 Authorization header -> authFn nil -> 下游通过 AuthHeaderFromContext 拿到原始值
	capture := &captureAuthHandler{}
	h := NewAuthMiddleware(nil, capture)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer test-token-123")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if capture.got != "Bearer test-token-123" {
		t.Fatalf("expected downstream to receive 'Bearer test-token-123', got %q", capture.got)
	}
}

func TestAuthMiddleware_AuthFnNilStillInjects(t *testing.T) {
	// authFn nil + 无 Authorization header -> 下游拿到的 authHeader 为空字符串（不 panic）
	capture := &captureAuthHandler{}
	h := NewAuthMiddleware(nil, capture)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if capture.got != "" {
		t.Fatalf("expected empty auth header, got %q", capture.got)
	}
}

func TestAuthMiddleware_AuthFnErrorDoesNotInject(t *testing.T) {
	// authFn 返回 error -> 下游不调用，不注入
	capture := &captureAuthHandler{}
	authFn := func(r *http.Request) error {
		return errUnauthorized("invalid token")
	}
	h := NewAuthMiddleware(authFn, capture)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer invalid")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if capture.got != "" {
		t.Fatalf("expected no injection on auth failure, but downstream received %q", capture.got)
	}
}

// errUnauthorized 是测试用的简单 error
type testError string

func (e testError) Error() string { return string(e) }

func errUnauthorized(msg string) error { return testError(msg) }
