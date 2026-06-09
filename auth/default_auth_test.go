package auth

// default_auth_test.go (P8 + P10)
//
// 验证 default_auth.go 的双层 Rego 行为：
//
//   兜底不变量层（P10 §3.3.1，DB 不可达时仍保证最小可用性）：
//     1a) ping/version/openapi-spec/debug + 内网 IP → 放行；外网 → 拒绝
//     1b) admin + 内网 IP + JWT.sub 非空 → 放行；外网或无 JWT → 拒绝
//     说明：P10 已删 v3 兜底中的 api+email_verified 分支（fail-safe），
//          也删了 admin+groups 兜底（统一由 DB 策略表达）。
//
//   DB 策略层（P8 actions-only 鉴权）：
//     2) DB allow 主路径：JWT.groups → role → policy(ALLOW) → action 完全匹配
//     3) DB allow 通配：service:* 前缀通配、"*" 全通配
//     4) DB deny 优先：同时存在 ALLOW + DENY 时整体不放行
//     5) DB 反查 subjects：JWT.sub → data.<pkg>.subjects.users → roles
//     6) 兜底安全：DataProvider 未挂载时 data.<pkg>.policies 等不存在 → DB 段
//        undefined，整体回落到兜底不变量层（仅 ping/version/admin 等放行）
//     7) 跨 role 聚合：单用户多个 role，任一 role 的 policy 命中即放行
//     8) action 不匹配：本路径不命中、且无任何不变量可放行时拒绝
//
// 实现要点：
//   - 走 NewClient → initOPARego → opaRego.Eval 全链路（不绕开 access_token 解析）
//   - 通过 OPARego.DataProvider 注入 dbloader 产物等价的 JSON，复用 newOPARegoConfig 的
//     PackageName="demo.example.v1" 保持与 P3 测试一致
//   - JWT 通过 encodeFakeJWT 构造（io.jwt.decode 不验签），形如 "Bearer base64h.base64p.sig"

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/open-policy-agent/opa/rego"
)

// ─────────────────────────────── helpers ───────────────────────────────

// encodeFakeJWT 生成一个未签名 JWT：header / payload base64URL 无填充，签名段任意字符串。
// 框架 access_token 规则使用 io.jwt.decode（仅解码、不验签），因此 sig 段填 "x" 也可。
func encodeFakeJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	// 注意：io.jwt.decode 要求签名段是合法 base64URL（即便不验签也要能 decode），
	// 单字符 "x" 不是合法 base64（最少 2 字符）—— 用 "AAAA" 既合法又显式表达"伪签名"。
	header := enc([]byte(`{"alg":"none","typ":"JWT"}`))
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal jwt payload: %v", err)
	}
	return header + "." + enc(body) + ".AAAA"
}

// dbDataProvider 返回一个 DataProvider，输出 dbloader 等价 schema 的 JSON：
//
//	{ "policies": {...}, "roles": {...}, "subjects": {...} }
//
// 注意：此 JSON 会被 client.go 与 envoy RBAC 合并到 data.<pkg>，
//
//	因为 parseEnvoyRBAC 先于合并执行且仅识别 envoy 字段，这里追加的 policies/roles/subjects
//	不会触发 protojson unknown field 错误（已在 P3 验证）。
//
// 形参 extra 用于补 envoy RBAC 必需的最小字段（action="ALLOW"，policies 空），
// 避免 unmarshal envoy 时报错。
func dbDataProvider(payload map[string]any) func(context.Context) ([]byte, error) {
	return func(_ context.Context) ([]byte, error) {
		// envoy RBAC 最小骨架 + dbloader 三段顶层键
		merged := map[string]any{
			// envoy RBAC 必备
			"action": "ALLOW",
			// "policies" 既是 envoy RBAC 字段又是 dbloader 字段；
			// envoy 端期望 object map (PolicyMap)，dbloader 这里也是 object，schema 兼容。
		}
		for k, v := range payload {
			merged[k] = v
		}
		return json.Marshal(merged)
	}
}

// newP8Config 在 newOPARegoConfig 基础上挂载 DataProvider。
// 同时清空 OPARego.Data —— 因为 DataProvider 优先；保留 Data 也只是给 nil-provider fallback 用。
func newP8Config(payload map[string]any) *Config {
	cfg := newOPARegoConfig(nil)
	cfg.OPARego.DataProvider = dbDataProvider(payload)
	return cfg
}

// evalAllow 构造完整 input（含 Bearer JWT + parsed_path + grpc_kit.action_id），
// 调用 opaRego.Eval 取 allow 结果。
func evalAllow(t *testing.T, c *Client, jwt string, parsedPath []string, actionID string) bool {
	t.Helper()
	ctx := context.Background()
	input := map[string]any{
		"parsed_path": parsedPath,
		"attributes": map[string]any{
			"source": map[string]any{
				"address": map[string]any{
					"socketAddress": map[string]any{
						// 默认外网，避免误中"内网放行"旧规则；测内网用例再覆盖
						"address": "8.8.8.8",
					},
				},
			},
			"request": map[string]any{
				"http": map[string]any{
					"headers": map[string]any{
						"authorization": "Bearer " + jwt,
					},
				},
			},
		},
		"grpc_kit": map[string]any{
			"action_id": actionID,
		},
	}
	rs, err := c.opaRego.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		t.Fatalf("opaRego.Eval err: %v", err)
	}
	if len(rs) == 0 {
		return false
	}
	v, ok := rs[0].Expressions[0].Value.(bool)
	if !ok {
		t.Fatalf("allow value not bool: %T %v", rs[0].Expressions[0].Value, rs[0].Expressions[0].Value)
	}
	return v
}

// stdDBPayload 返回一个常用的小型 db 数据集：
//
//	role "developer" → policy "read_demo"  (ALLOW demo.example.v1:Item.Get)
//	role "ops"       → policy "all_demo"   (ALLOW demo.example.v1:*)
//	role "auditor"   → policy "read_any"   (ALLOW *)
//	role "guest"     → policy "deny_get"   (DENY demo.example.v1:Item.Get)
//	role "alice"     → user sub "u-001" 绑定到 ["developer"]
func stdDBPayload() map[string]any {
	return map[string]any{
		"policies": map[string]any{
			"read_demo": map[string]any{
				"code": "read_demo",
				"statements": []map[string]any{
					{"effect": "ALLOW", "actions": []string{"demo.example.v1:Item.Get"}, "resources": []string{}, "conditions": []any{}},
				},
			},
			"all_demo": map[string]any{
				"code": "all_demo",
				"statements": []map[string]any{
					{"effect": "ALLOW", "actions": []string{"demo.example.v1:*"}, "resources": []string{}, "conditions": []any{}},
				},
			},
			"read_any": map[string]any{
				"code": "read_any",
				"statements": []map[string]any{
					{"effect": "ALLOW", "actions": []string{"*"}, "resources": []string{}, "conditions": []any{}},
				},
			},
			"deny_get": map[string]any{
				"code": "deny_get",
				"statements": []map[string]any{
					{"effect": "DENY", "actions": []string{"demo.example.v1:Item.Get"}, "resources": []string{}, "conditions": []any{}},
				},
			},
		},
		"roles": map[string]any{
			"developer": map[string]any{"parent": "", "policies": []string{"read_demo"}},
			"ops":       map[string]any{"parent": "", "policies": []string{"all_demo"}},
			"auditor":   map[string]any{"parent": "", "policies": []string{"read_any"}},
			"guest":     map[string]any{"parent": "", "policies": []string{"deny_get"}},
		},
		"subjects": map[string]any{
			"users":       map[string]any{"u-001": []string{"developer"}},
			"groups":      map[string]any{},
			"departments": map[string]any{},
		},
	}
}

// ─────────────────────────────── tests ───────────────────────────────

// 1a) 兜底不变量：未挂 DataProvider 时，ping 仅在内网放行；外网拒绝。
func TestDefaultAuth_PingRule_InternalOnly(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, newOPARegoConfig(nil))
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}

	mkInput := func(addr string) map[string]any {
		return map[string]any{
			"parsed_path": []string{"ping"},
			"attributes": map[string]any{
				"source": map[string]any{"address": map[string]any{"socketAddress": map[string]any{"address": addr}}},
				"request": map[string]any{"http": map[string]any{"headers": map[string]any{}}},
			},
		}
	}

	rs, err := c.opaRego.Eval(ctx, rego.EvalInput(mkInput("127.0.0.1")))
	if err != nil {
		t.Fatalf("Eval internal err: %v", err)
	}
	if len(rs) == 0 || rs[0].Expressions[0].Value != true {
		t.Fatalf("expected ping allow=true from internal IP, got %+v", rs)
	}

	rs, err = c.opaRego.Eval(ctx, rego.EvalInput(mkInput("8.8.8.8")))
	if err != nil {
		t.Fatalf("Eval external err: %v", err)
	}
	if len(rs) > 0 && rs[0].Expressions[0].Value == true {
		t.Fatalf("expected ping allow=false from external IP, got %+v", rs)
	}
}

// 2) DB allow 主路径：JWT.groups=["developer"] + action 完全匹配 → 放行
func TestDefaultAuth_DBAllow_ExactActionMatch(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, newP8Config(stdDBPayload()))
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	jwt := encodeFakeJWT(t, map[string]any{
		"sub":    "u-999",
		"groups": []string{"developer"},
	})
	if !evalAllow(t, c, jwt, []string{"api"}, "demo.example.v1:Item.Get") {
		t.Fatalf("expected allow=true for developer:Item.Get")
	}
}

// 3a) DB allow 通配：service:* 前缀通配 → 放行任意该服务的 action
func TestDefaultAuth_DBAllow_ServicePrefixWildcard(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, newP8Config(stdDBPayload()))
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	jwt := encodeFakeJWT(t, map[string]any{
		"groups": []string{"ops"}, // policy=all_demo, actions=["demo.example.v1:*"]
	})
	if !evalAllow(t, c, jwt, []string{"api"}, "demo.example.v1:Anything.Else") {
		t.Fatalf("expected allow=true for ops on demo.example.v1:Anything.Else (svc:* wildcard)")
	}
	// 不同 service 的 action 不应命中 svc:* 通配
	if evalAllow(t, c, jwt, []string{"api"}, "other.svc.v1:Foo.Bar") {
		t.Fatalf("expected allow=false for ops on other.svc.v1:Foo.Bar (svc-prefix shouldn't cross)")
	}
}

// 3b) DB allow 通配："*" 全通配 → 放行任意 action
func TestDefaultAuth_DBAllow_StarWildcard(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, newP8Config(stdDBPayload()))
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	jwt := encodeFakeJWT(t, map[string]any{
		"groups": []string{"auditor"}, // policy=read_any, actions=["*"]
	})
	if !evalAllow(t, c, jwt, []string{"api"}, "anything.v9:Goes.Here") {
		t.Fatalf("expected allow=true for auditor on anything (star wildcard)")
	}
}

// 4) DENY 优先：同时持有 ALLOW(read_demo) 与 DENY(deny_get) → 整体不放行
func TestDefaultAuth_DBDeny_OverridesAllow(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, newP8Config(stdDBPayload()))
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	jwt := encodeFakeJWT(t, map[string]any{
		"groups": []string{"developer", "guest"}, // ALLOW + DENY 同一 action
	})
	// 该 action 必须**只**走 DB 路径才能测到 DENY 优先；
	// parsed_path[0]="api" 同时也命中旧规则"api + email_verified" 的前置条件，
	// 但旧规则要求 payload.email_verified==true，故此处 payload 未给 email_verified 时旧规则不命中，
	// 唯一可能放行的就是 DB 路径 → DENY 优先后整体应为 false。
	if evalAllow(t, c, jwt, []string{"api"}, "demo.example.v1:Item.Get") {
		t.Fatalf("expected allow=false (DENY should override ALLOW)")
	}
}

// 5) JWT.sub 反查 subjects.users：用户无 groups 但 sub=u-001 已绑 developer → 放行
func TestDefaultAuth_DBAllow_SubjectsUsersLookup(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, newP8Config(stdDBPayload()))
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	jwt := encodeFakeJWT(t, map[string]any{
		"sub": "u-001", // 无 groups 字段
	})
	if !evalAllow(t, c, jwt, []string{"api"}, "demo.example.v1:Item.Get") {
		t.Fatalf("expected allow=true via subjects.users[u-001]=[developer]")
	}
}

// 6) 兜底安全：DataProvider 未挂载时（即没有 data.<pkg>.policies/roles/subjects），
// 业务 action 必然走不通 DB 段；进而需走兜底不变量层 —— api/* 路径在 P10 后已无兜底
// 放行规则（v3 的 email_verified 兜底被删，fail-safe），唯一可命中的内网 + admin 路径
// 是兜底层的 admin 不变量。
//
// 1b) admin 兜底：内网 + JWT.sub 非空 → 放行；无 JWT 或外网 → 拒绝；
//     业务 api 路径无 DB 时一律拒绝（fail-safe）。
func TestDefaultAuth_NoDB_AdminInvariantFallback(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, newOPARegoConfig(nil))
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}

	jwtWithSub := encodeFakeJWT(t, map[string]any{"sub": "u-1"})

	mkInput := func(parsedPath []string, addr, auth string) map[string]any {
		return map[string]any{
			"parsed_path": parsedPath,
			"attributes": map[string]any{
				"source": map[string]any{"address": map[string]any{"socketAddress": map[string]any{"address": addr}}},
				"request": map[string]any{"http": map[string]any{"headers": map[string]any{
					"authorization": auth,
				}}},
			},
		}
	}

	check := func(name string, in map[string]any, want bool) {
		t.Helper()
		rs, err := c.opaRego.Eval(ctx, rego.EvalInput(in))
		if err != nil {
			t.Fatalf("%s: Eval err: %v", name, err)
		}
		got := len(rs) > 0 && rs[0].Expressions[0].Value == true
		if got != want {
			t.Fatalf("%s: expected allow=%v, got %v (rs=%+v)", name, want, got, rs)
		}
	}

	// admin 内网 + 已登录 → 放行
	check("admin internal+jwt", mkInput([]string{"admin"}, "10.1.2.3", "Bearer "+jwtWithSub), true)
	// admin 外网 → 拒绝
	check("admin external+jwt", mkInput([]string{"admin"}, "8.8.8.8", "Bearer "+jwtWithSub), false)
	// admin 内网但无 JWT → 拒绝（v3 admin 兜底已删，新兜底强制要 sub）
	check("admin internal noauth", mkInput([]string{"admin"}, "10.1.2.3", ""), false)
	// 业务 api/* 路径 + 有效 JWT → DB 不可达时 fail-safe 拒绝（P10 已删 email_verified 兜底）
	check("api fail-safe", mkInput([]string{"api"}, "10.1.2.3", "Bearer "+jwtWithSub), false)
}

// 7) 跨 role 聚合：JWT.groups=[ops, guest]，对一个 ops:Anything 命中 ALLOW 且 guest 的 DENY 仅覆盖 Item.Get
// → 对 Item.List 应放行（DENY 不匹配 Item.List），对 Item.Get 应拒绝（DENY 命中）
func TestDefaultAuth_MultiRoleAggregation_DenyScoped(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, newP8Config(stdDBPayload()))
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	jwt := encodeFakeJWT(t, map[string]any{
		"groups": []string{"ops", "guest"},
	})
	// Item.List → ops 的 svc:* ALLOW 命中；guest 的 DENY 仅针对 Item.Get → 放行
	if !evalAllow(t, c, jwt, []string{"api"}, "demo.example.v1:Item.List") {
		t.Fatalf("expected allow=true for Item.List (DENY only scoped to Item.Get)")
	}
	// Item.Get → 同时命中 ops 的 svc:* ALLOW 与 guest 的 DENY → 拒绝
	if evalAllow(t, c, jwt, []string{"api"}, "demo.example.v1:Item.Get") {
		t.Fatalf("expected allow=false for Item.Get (DENY scoped match)")
	}
}

// 8) action 不匹配 + 无旧规则可放行 → 拒绝
func TestDefaultAuth_DBNoMatch_AndNoLegacy_Denies(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, newP8Config(stdDBPayload()))
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	jwt := encodeFakeJWT(t, map[string]any{
		"groups":         []string{"developer"}, // 仅 read_demo（Item.Get）
		"email_verified": false,                  // 排除旧 api 规则
	})
	// developer 的 policy 不覆盖 Item.Delete，且 email_verified=false → 旧规则不放行
	if evalAllow(t, c, jwt, []string{"api"}, "demo.example.v1:Item.Delete") {
		t.Fatalf("expected allow=false for Item.Delete (no policy match, no legacy fallback)")
	}
}

// 9) DB 路径不消费 resources/conditions：即使 resources 为空数组 / conditions 含未知 operator，
// 也不影响 ALLOW 命中（Phase 1 仅按 actions 鉴权）
func TestDefaultAuth_DBAllow_IgnoresResourcesAndConditions(t *testing.T) {
	ctx := context.Background()
	payload := map[string]any{
		"policies": map[string]any{
			"p1": map[string]any{
				"code": "p1",
				"statements": []map[string]any{
					{
						"effect":     "ALLOW",
						"actions":    []string{"svc.v1:Do.It"},
						"resources":  []string{"grn:public:svc:cn::item/123"}, // 任意值，Phase 1 不消费
						"conditions": []map[string]any{{"key": "x", "operator": "ZZZ", "values": []string{"y"}}},
					},
				},
			},
		},
		"roles": map[string]any{
			"r1": map[string]any{"parent": "", "policies": []string{"p1"}},
		},
		"subjects": map[string]any{
			"users": map[string]any{}, "groups": map[string]any{}, "departments": map[string]any{},
		},
	}
	c, err := NewClient(ctx, newP8Config(payload))
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	jwt := encodeFakeJWT(t, map[string]any{"groups": []string{"r1"}})
	if !evalAllow(t, c, jwt, []string{"api"}, "svc.v1:Do.It") {
		t.Fatalf("expected allow=true (Phase 1 should ignore resources/conditions)")
	}
}
