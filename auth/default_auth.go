package auth

import "fmt"

func (c *Config) defaultRego() []byte {
	return []byte(fmt.Sprintf(`
package %s

# import rego.v1

import future.keywords.if
import future.keywords.in

import data.%s.action
import data.%s.policies

default allow := false

# 允许所有客户端请求以下 url 前缀地址
allow if {
    some url in ["ping"]
    url == input.parsed_path[0]
}

# 仅允许特定内网访问以下 url 前缀地址
allow if {
    some url in ["version", "openapi-spec", "debug"]
    url == input.parsed_path[0]

    some cidr in ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    net.cidr_contains(cidr, input.attributes.source.address.socketAddress.address)
}

# 仅允许特定内网且必须登录后才可访问管理后台
allow if {
    input.parsed_path[0] == "admin"

    some cidr in ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    net.cidr_contains(cidr, input.attributes.source.address.socketAddress.address)

    some x, _ in policies
    x in data.%s.access_token.payload.groups
}

# 所有接口请求必须认证且邮箱地址必须是验证过
allow if {
    input.parsed_path[0] == "api"

    data.%s.access_token.payload.email_verified == true
}

# 解析 jwt token 这里不做签名串验证
access_token := {"payload": payload} if {
    [_, encoded] := split(input.attributes.request.http.headers.authorization, " ")
    [header, payload, sig] := io.jwt.decode(encoded)
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
# 身份来源：现阶段 input.subject 未注入，复用既有 access_token 规则从 JWT payload 取
#   - payload.groups → 直接当 role code 集合（兼容当前 OIDC group 直接对应角色的约定）
#   - payload.sub    → 反查 data.%s.subjects.users 拿到绑定角色集合
#
# 设计原则：
#   1) **不删除任何旧规则**，本块仅在原 ping/version/admin/api 5 条 allow 之后追加；
#   2) DENY 优先：任一 DENY 匹配则整条 db_allow 不成立；
#   3) Action 三层通配：完整匹配 / "svc.code:*" 前缀 / "*" 全匹配；
#   4) Phase 1 暂不消费 statement.resources / statement.conditions，留给 P11+；
#   5) DataProvider 未挂载时（如本期 P8 cfg 层未接入），data.%s.policies 等不存在
#      → 各 db_xxx 表达式 undefined → 本块 allow 不命中，自然降级到旧规则，零回归。
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

# 主入口：DENY 优于 ALLOW
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
		c.PackageName, // import data.%s.action
		c.PackageName, // import data.%s.policies
		c.PackageName, // admin 块 data.%s.access_token.payload.groups
		c.PackageName, // api 块 data.%s.access_token.payload.email_verified
		// ── P8 追加块的 %s 占位 ──
		c.PackageName, // 注释：注入到 data.%s 命名空间下
		c.PackageName, // 注释：data.%s.policies
		c.PackageName, // 注释：data.%s.roles
		c.PackageName, // 注释：data.%s.subjects
		c.PackageName, // 注释：payload.sub 反查 data.%s.subjects.users
		c.PackageName, // 注释：DataProvider 未挂载时 data.%s.policies 等不存在
		c.PackageName, // db_token_roles: data.%s.subjects.users
		c.PackageName, // db_policy_codes: data.%s.roles
		c.PackageName, // allow: data.%s.policies
		c.PackageName, // db_deny_matched: data.%s.policies
	))
}
