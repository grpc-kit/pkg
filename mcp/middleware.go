package mcp

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// AuthFunc 是 MCP 认证回调函数签名。
// 验证成功返回 nil，失败返回 error。
// pkg/cfg.SecurityConfig.VerifyHTTPRequest 满足此签名。
type AuthFunc func(r *http.Request) error

// NewAuthMiddleware 创建 HTTP 认证中间件。
// 若 authFn 为 nil 则直接放行（无认证模式）；
// 否则在调用下游 handler 前执行认证，失败时返回 401 JSON 错误。
func NewAuthMiddleware(authFn AuthFunc, next http.Handler) http.Handler {
	if authFn == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := authFn(r); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}
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
