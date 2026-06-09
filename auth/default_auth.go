package auth

import "fmt"

// defaultRego 返回框架内置兜底 Rego。
//
// Phase 1 P10：精简为 §3.3.1 描述的最小不变量 + P8 DB 策略段。
//
// 旧版（v3）有 5 条 envoy 风格 allow（ping / version-cidr / admin-cidr-groups /
// api-email_verified / access_token-decode）共 60+ 行，逻辑与协议无关层重叠且
// 包含「业务接口 api/* 默认验证邮箱」这类不合理兜底。新版只保留两条不变量：
//
//   - 不变量 1：健康检查 / 元数据端点 (ping/version/openapi-spec/debug) 内网放行
//   - 不变量 2：管理后台 (/admin) 仅内网且 JWT sub 非空可访问
//
// 业务接口 (api/*) 兜底逻辑被**删除** —— 业务策略 MUST 由 DataProvider 注入；
// DB 不可用时业务接口应当 fail-safe 拒绝，而非走 email_verified 之类弱约束。
//
// 选型说明（Phase 1 范围限定）：本期 (P10) 不重构 Allow() 的 input 构造，故
// 不变量字段沿用当前 envoy 风格 input：
//   - 协议判定：暂不消费 input.protocol（当前 Allow 唯一入口走 HTTP / gRPC 转换）
//   - 远端 IP：input.attributes.source.address.socketAddress.address
//   - JWT sub：复用 P8 段已有的 access_token 规则解 Authorization header
//
// 协议无关 input（input.protocol / input.transport.remote_addr / input.subject.id）
// 留待 §3.4「Allow 协议无关化」专项重构（Phase 2）。
//
// P8 DB 策略段（actions-only 鉴权）原样保留，仍位于本兜底 Rego 中：
// DataProvider 未挂载时 data.<pkg>.policies 等不存在 → db_xxx 表达式 undefined
// → DB 段 allow 不命中，自然降级到上面两条不变量，零回归。
func (c *Config) defaultRego() []byte {
	return []byte(fmt.Sprintf(`
package %s

import future.keywords.if
import future.keywords.in

default allow := false

# ────────────────────────────────────────────────────────────────────────────────
# Phase 1 P10 兜底不变量（DB 不可达时仍保证最小可用性）
# ────────────────────────────────────────────────────────────────────────────────

# 不变量 1：内网 + 健康检查 / 元数据端点 永远放行
allow if {
    some path in ["ping", "version", "openapi-spec", "debug"]
    path == input.parsed_path[0]
    is_internal_ip(input.attributes.source.address.socketAddress.address)
}

# 不变量 2：管理后台 (/admin) 仅内网 + 已通过 JWT 验证 (sub 非空) 的用户可访问
allow if {
    input.parsed_path[0] == "admin"
    is_internal_ip(input.attributes.source.address.socketAddress.address)
    access_token.payload.sub != ""
    access_token.payload.sub != "0"
}

is_internal_ip(addr) if {
    some cidr in ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    net.cidr_contains(cidr, addr)
}

# 解析 jwt token 这里不做签名串验证（兜底 + P8 DB 段共用）
access_token := {"payload": payload} if {
    [_, encoded] := split(input.attributes.request.http.headers.authorization, " ")
    [_, payload, _] := io.jwt.decode(encoded)
}

# ────────────────────────────────────────────────────────────────────────────────
# P8: DB 策略 actions-only 鉴权（Phase 1）
#
# 数据来源约定（由 pkg/auth/dbloader.go 在 DataProvider 注入到 data.%s 命名空间下）：
#
#   data.%s.policies = { "<policy_code>": {
#       "code": "...",
#       "statements": [
#           { "effect": "ALLOW"|"DENY", "actions": ["svc.code:action.code"|"svc.code:*"|"*", ...],
#             "resources": [...], "conditions": [...] }
#       ]
#   } }
#   data.%s.roles    = { "<role_code>":   { "parent": "...", "policies": ["<policy_code>", ...] } }
#   data.%s.subjects = { "users": { "<sub>": ["<role_code>", ...] }, "groups": {...}, "departments": {...} }
#
# 身份来源：
#   - payload.groups → 直接当 role code 集合（兼容当前 OIDC group 直接对应角色的约定）
#   - payload.sub    → 反查 data.%s.subjects.users 拿到绑定角色集合
#
# 设计原则：
#   1) DENY 优先：任一 DENY 匹配则整条 allow 不成立；
#   2) Action 三层通配：完整匹配 / "svc.code:*" 前缀 / "*" 全匹配；
#   3) Phase 1 暂不消费 statement.resources / statement.conditions，留给 P11+；
#   4) DataProvider 未挂载时（如本期 P8 cfg 层未接入），data.%s.policies 等不存在
#      → 各 db_xxx 表达式 undefined → 本块 allow 不命中，自然降级到上面兜底不变量。
# ────────────────────────────────────────────────────────────────────────────────

db_token_groups := gs if {
    gs := access_token.payload.groups
} else := []

db_token_sub := s if {
    s := access_token.payload.sub
} else := ""

db_token_roles := array.concat(
    db_token_groups,
    object.get(data.%s.subjects.users, db_token_sub, []),
)

db_policy_codes := {p |
    some r in db_token_roles
    some p in data.%s.roles[r].policies
}

# DB 段入口：DENY 优于 ALLOW
allow if {
    not db_deny_matched
    some pcode in db_policy_codes
    some stmt in data.%s.policies[pcode].statements
    stmt.effect == "ALLOW"
    db_action_matched(stmt.actions, input.grpc_kit.action_id)
}

db_deny_matched if {
    some pcode in db_policy_codes
    some stmt in data.%s.policies[pcode].statements
    stmt.effect == "DENY"
    db_action_matched(stmt.actions, input.grpc_kit.action_id)
}

# Action 三层通配
db_action_matched(actions, _) if "*" in actions

db_action_matched(actions, want) if want in actions

db_action_matched(actions, want) if {
    some a in actions
    endswith(a, ":*")
    startswith(want, trim_suffix(a, "*"))
}
`,
		c.PackageName, // package %s
		// ── P8 注释块占位 ──
		c.PackageName, // 注释：注入到 data.%s 命名空间
		c.PackageName, // 注释：data.%s.policies
		c.PackageName, // 注释：data.%s.roles
		c.PackageName, // 注释：data.%s.subjects
		c.PackageName, // 注释：payload.sub 反查 data.%s.subjects.users
		c.PackageName, // 注释：DataProvider 未挂载时 data.%s.policies 等不存在
		// ── 实际规则占位 ──
		c.PackageName, // db_token_roles: data.%s.subjects.users
		c.PackageName, // db_policy_codes: data.%s.roles
		c.PackageName, // allow: data.%s.policies
		c.PackageName, // db_deny_matched: data.%s.policies
	))
}
