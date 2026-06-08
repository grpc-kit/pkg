// 协议无关 OPA input 构造器（Phase 1 / P5 — 最小版）
//
// 本文件提供 `FromGRPCContext` / `FromHTTPRequest` 两个入口，把来自不同协议
// （原生 gRPC、grpc-gateway 桥接、纯 HTTP 端点）的请求统一翻译为 OPA Rego
// 评估所需的 `input` 树骨架（仅含 `subject` + `grpc_kit.{service,action,action_id}`）。
//
// **当前阶段（P5）刻意保持最小化**：
//
//   - **未接入** `Client.Allow()`；框架运行时行为零变化。
//   - 仅依赖 P2/P3 已就绪的 `StaticDict.RPCRoutes` / `GatewayRoutes` 做反查。
//   - **不填** `resources` / `condition_ctx` 等业务字段（留待 P12）。
//   - **不做** GRN 占位符渲染（`${partition}` 等留待 P12 由 input_builder 注入）。
//   - **subject 仅占位**：本期返回空 `Subject{}`，由后续期（P6 安装到 Allow 链路时）
//     从 IDToken / metadata 中提取。
//
// 与文档 §3.2 / §3.4 对齐；详见 `adm/docs/roadmap/permission-opa-policy-loader.md` §6.2-P5。

package auth

import (
	"context"
	"net/http"
	"strings"

	"google.golang.org/grpc"
)

// Subject 调用主体（authenticated principal）的最小字段集。
//
// 本期占位为空结构；P6 接入 `Allow()` 时由 IDToken / metadata 填充
// （`sub` / `email` / `groups` / `tenant` 等）。
type Subject struct {
	// 留空 —— 字段在 P6 起根据 spec §3.2 input.subject 章节扩展。
}

// GrpcKit OPA input 中 `input.grpc_kit.*` 子树。
//
// 字段一一对应文档 §3.2 “统一 input 协议”的 `grpc_kit` 节，本期仅填充其中三个：
//
//   - Service     —— svc_code，如 "known.admin.api"
//   - Action      —— action 名，如 "CreateAuthLogin"
//   - ActionID    —— "<svc_code>:<action>"，如 "known.admin.api:CreateAuthLogin"
//
// 其余字段（`resources` / `condition_ctx` / `protocol` ...）由后续期补齐。
type GrpcKit struct {
	// Service 服务编码（StaticDict.Services 的 key）。反查未命中时为空字符串。
	Service string

	// Action 动作编码（grpc method 名，等价于 Service.Actions 的 key）。
	// 反查未命中时为空字符串。
	Action string

	// ActionID 形如 `<Service>:<Action>`，对应 StaticDict.RPCRoutes 的 value
	// 与 GatewayRoutes[i].ActionID。
	ActionID string
}

// Input 是注入到 OPA `rego.EvalInput(...)` 的根对象。
//
// 序列化时刻意使用 `map[string]any` 而非该结构体本身，便于未来与既有
// envoy 风格字段（`attributes` / `parsed_path` 等）做"去重并集"合并；
// 见 `(*Input).ToMap()`。
type Input struct {
	Subject Subject
	GrpcKit GrpcKit
}

// ToMap 把 Input 扁平化为 OPA 期望的 map 结构。
//
// 输出形如：
//
//	{
//	  "subject":  {},                                              // 本期占位
//	  "grpc_kit": {"service": "...", "action": "...", "action_id": "..."},
//	}
//
// 字段缺失（如 StaticDict 反查未命中）时仍保留键，便于 Rego 用
// `input.grpc_kit.service == ""` 区分"未注册动作"。
func (in *Input) ToMap() map[string]any {
	return map[string]any{
		"subject": map[string]any{},
		"grpc_kit": map[string]any{
			"service":   in.GrpcKit.Service,
			"action":    in.GrpcKit.Action,
			"action_id": in.GrpcKit.ActionID,
		},
	}
}

// FromGRPCContext 从 gRPC server 拦截器的 ctx 构造 input 骨架。
//
// 反查逻辑：
//
//  1. 通过 `grpc.Method(ctx)` 取得 `/<grpc_service>/<method>`。
//  2. 在 `dict.RPCRoutes` 中查 `action_id`，命中则拆出 `service` / `action`。
//
// 当 ctx 中无 gRPC method（非拦截器栈调用）或 `dict == nil` 时，
// 返回非 nil 的 `*Input`，但 `GrpcKit` 字段全为空字符串——交由调用方
// 决定降级到 `FromHTTPRequest` 还是放行/拒绝。
func FromGRPCContext(ctx context.Context, dict *StaticDict) *Input {
	in := &Input{}

	method, ok := grpc.Method(ctx)
	if !ok || method == "" || dict == nil {
		return in
	}

	actionID, hit := dict.RPCRoutes[method]
	if !hit {
		return in
	}

	in.GrpcKit = splitActionID(actionID)
	return in
}

// FromHTTPRequest 从纯 HTTP 端点（非 grpc-gateway，例如 `/ping` / `/debug`）
// 构造 input 骨架。
//
// 反查逻辑：
//
//  1. 取 `req.Method`（大写）+ `req.URL.Path`。
//  2. 在 `dict.GatewayRoutes` 中查 method **完全相等**且 PathTemplate **字面相等**
//     的第一条；未命中返回空 GrpcKit。
//
// **本期刻意不实现 grpc-gateway 风格的 `{var=pat}` path template 匹配**——
// 该能力留待 P5+（路由表反查能力增强）或 §3.4 真正接入 Allow 时再补。
// 因此本函数本期只对纯字面路径（如 `/ping`、`/version`、`/debug/pprof/profile`）
// 有效；带 `{}` 占位符的 gateway 路由会被静默跳过（返回空 GrpcKit）。
func FromHTTPRequest(ctx context.Context, req *http.Request, dict *StaticDict) *Input {
	_ = ctx // 保留参数以保持与 FromGRPCContext 对称，便于未来注入 subject 等。

	in := &Input{}
	if req == nil || dict == nil {
		return in
	}

	method := strings.ToUpper(req.Method)
	path := ""
	if req.URL != nil {
		path = req.URL.Path
	}

	for _, r := range dict.GatewayRoutes {
		if !strings.EqualFold(r.Method, method) {
			continue
		}
		// 字面相等匹配（不解析 `{var=pat}`）——见上方注释。
		if r.PathTemplate != path {
			continue
		}
		in.GrpcKit = splitActionID(r.ActionID)
		return in
	}

	return in
}

// splitActionID 把 "svc_code:Action" 拆为 GrpcKit 三字段。
// 输入非法（无冒号、空段）时返回空 GrpcKit（service/action 均空），
// 但 ActionID 字段原样保留，便于 Rego 侧调试。
func splitActionID(actionID string) GrpcKit {
	gk := GrpcKit{ActionID: actionID}
	idx := strings.IndexByte(actionID, ':')
	if idx <= 0 || idx == len(actionID)-1 {
		return gk
	}
	gk.Service = actionID[:idx]
	gk.Action = actionID[idx+1:]
	return gk
}
