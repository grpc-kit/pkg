package mcp

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// AuthFunc 是 MCP 认证回调函数签名。
// 验证成功返回 nil，失败返回 error。
// pkg/cfg.SecurityConfig.VerifyHTTPRequest 满足此签名。
type AuthFunc func(r *http.Request) error

// authHeaderKey 是用于在 context 中传递原始 Authorization header 的 key。
// 通过 unexported struct 类型避免与其他包的 context key 冲突。
type authHeaderKey struct{}

// ContextWithAuthHeader 返回一个携带 Authorization header 值的子 context。
// 调用方通常是 HTTP 中间件，把客户端原始 Authorization 注入 context，
// 供下游的 MCP tool handler 透传到 outgoing HTTP 请求（如 AutoBridge 调用 gateway）。
func ContextWithAuthHeader(parent context.Context, authHeader string) context.Context {
	return context.WithValue(parent, authHeaderKey{}, authHeader)
}

// AuthHeaderFromContext 从 context 中取出 Authorization header 值。
// 若 context 中不存在则返回空字符串。
func AuthHeaderFromContext(ctx context.Context) string {
	v, _ := ctx.Value(authHeaderKey{}).(string)
	return v
}

// NewAuthMiddleware 创建 HTTP 认证中间件。
// 若 authFn 为 nil 则直接放行（无认证模式）；
// 否则在调用下游 handler 前执行认证，失败时返回 401 JSON 错误。
//
// 无论 authFn 是否 nil，本中间件都会通过 r.WithContext 把原始 Authorization
// header 注入到请求 context，使下游 AutoBridge tool handler 能透传给 gateway。
// 这样即便 SecurityConfig.Enable=false（authFn=nil），客户端携带的 Authorization
// 仍可被透传到 gateway，保证审计与鉴权链路完整。
func NewAuthMiddleware(authFn AuthFunc, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authFn != nil {
			if err := authFn(r); err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": err.Error(),
				})
				return
			}
		}
		// 注入原始 Authorization header 到 context，供 AutoBridge 透传给 gateway。
		// authFn=nil 时也注入（可能为空字符串），保证未启用认证场景行为一致。
		r = r.WithContext(ContextWithAuthHeader(r.Context(), r.Header.Get("Authorization")))
		next.ServeHTTP(w, r)
	})
}

// statusRecorder 捕获响应状态码，供日志中间件使用
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

// LoggingMiddleware 是简易的 HTTP 请求日志中间件，
// 记录 method、path、status 和 duration。
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sr, r)
		log.Printf("mcp %s %s -> %d (%v)", r.Method, r.URL.Path, sr.status, time.Since(start))
	})
}
