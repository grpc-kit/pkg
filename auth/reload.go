package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Phase 1 P9：策略主动刷新。
//
// 设计要点（与 roadmap §3.5 / §6.2 P9 行一一对应）：
//
//   - **复用 initOPARego 全部逻辑**：包括 DataProvider 调用、StaticDict 合并、
//     defaultRego/defaultData 兜底、PackageName 嵌套包名构造。Reload 不重写任何
//     load/parse/build 逻辑，避免"主路径与刷新路径行为漂移"。
//
//   - **失败不替换**：initOPARego 内部所有 return err 都发生在 `c.opaRego = query`
//     之前（见 client.go），所以 initOPARego 报错时 c.opaRego 与 c.opaData 自动保持
//     旧值不变；调用方收到 wrap err 即可记录/告警，旧规则仍生效。这是"失败时不替换"
//     语义的天然实现，无需 Reload 自己做 try-and-swap。
//
//   - **并发安全**：`c.opaRego` 的读 / 写已经在 client.go::Allow / initOPARego 里
//     用 `c.mu` RLock/Lock 保护；Reload 只是把 initOPARego 当作"持写锁的完整刷新"
//     调用一次，不需要在 Reload 这一层再加锁。
//
//   - **HTTP 端点**：仅接受 POST，避免 GET 误触发（浏览器预热 / 监控探针）。
//     端点本身不做 RBAC —— 它就是 RBAC 数据的刷新入口，强制走业务方在 admin mux
//     上叠加的内网兜底（IP 白名单 / mTLS / 反向代理 ACL）。响应固定 JSON 便于
//     curl + jq 排错。

// Reload 重新加载策略数据并替换内部 OPA query。
//
// 调用方场景：
//   - 业务在管理后台触发"重载策略"按钮
//   - cfg 层接到 etcd watch / DB CDC 事件
//   - 启动时显式调用一次保证刷新链路可用
//
// 返回的 error 已 wrap initOPARego 原始错误，调用方可直接日志输出。
func (c *Client) Reload(ctx context.Context) error {
	if c == nil || c.config == nil || c.config.OPARego == nil {
		// 未启用 OPARego 模式 —— Reload 在语义上是 no-op。
		return nil
	}

	if err := c.initOPARego(ctx); err != nil {
		return fmt.Errorf("reload opa rego: %w", err)
	}
	return nil
}

// RegisterReloadHandler 在指定 ServeMux 上注册策略刷新端点。
//
// 端点契约：
//
//	POST /admin/live/reload-policies
//	  请求体：忽略（保留给后续期传递 trace_id / 重试 budget 等）
//	  成功 200：{"status":"ok"}
//	  失败 500：{"status":"error","error":"<wrap-err>"}
//	  非 POST 405：{"status":"error","error":"method not allowed"}
//
// 路径选择固定 `/admin/live/reload-policies`，与 roadmap §3.5 表一致；
// 若业务方需要自定义路径，可绕过本函数自行 `mux.HandleFunc(path, c.reloadHandler)`
// （`reloadHandler` 当前未导出 —— 业务方有需要时再加 With-Option 模式重构）。
//
// **本端点不做 RBAC**：刷新本身就是 RBAC 数据更新入口，由业务方在 mux 外层
// 叠加内网兜底（IP 白名单 / mTLS / sidecar ACL）。
func (c *Client) RegisterReloadHandler(mux *http.ServeMux) {
	if mux == nil || c == nil {
		return
	}
	mux.HandleFunc("/admin/live/reload-policies", c.reloadHandler)
}

// reloadHandler 是 RegisterReloadHandler 的内部实现，单独导出便于测试 + 业务自定义路径。
func (c *Client) reloadHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"error":  "method not allowed; use POST",
		})
		return
	}

	if err := c.Reload(r.Context()); err != nil {
		c.logger.Warnf("reload policies failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}
