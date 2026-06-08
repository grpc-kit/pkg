package auth

import (
	"context"
	"testing"
	"testing/fstest"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/open-policy-agent/opa/rego"
)

// 与 static_dict_test.go 同源的最小 gateway/openapi 资产；
// 局部常量避免跨文件耦合（每个测试文件自封）。
// selector 段 → parts[3].parts[4].parts[2] = demo.v1.example
const p3GatewayYAML = `type: google.api.Service
config_version: 3
name: demo.example.api
title: Demo Service
apis:
  - name: grpc_kit.api.example.demo.v1.Demo
http:
  rules:
    - selector: grpc_kit.api.example.demo.v1.Demo.ListItems
      get: /api/v1/items
    - selector: grpc_kit.api.example.demo.v1.Demo.GetItem
      get: /api/v1/items/{name}
`

const p3OpenAPIYAML = `swagger: "2.0"
info:
  title: Demo
  version: v1
paths:
  /api/v1/items:
    get:
      operationId: Demo_ListItems
      tags: [demo]
      summary: list items
  /api/v1/items/{name}:
    get:
      operationId: Demo_GetItem
      tags: [demo]
      summary: get one
`

func p3FixtureFS(t *testing.T) fstest.MapFS {
	t.Helper()
	return fstest.MapFS{
		"openapi/microservice.gateway.yaml":   {Data: []byte(p3GatewayYAML)},
		"openapi/microservice.openapiv2.yaml": {Data: []byte(p3OpenAPIYAML)},
	}
}

// newOPARegoConfig 构造一个最小可工作的 OPARego Config。
// Rego 留空走框架默认；Data 给一个合法的空 envoy RBAC（parseEnvoyRBAC 要求 protojson-compatible）。
// StaticDict 为 nil 时表示不注入静态字典。
func newOPARegoConfig(staticDict *StaticDict) *Config {
	return &Config{
		PackageName: "demo.example.v1",
		OPARego: &OPARegoConfig{
			Rego: nil,
			// 最小合法 envoy RBAC：仅含 action 字段，避免触发 parseEnvoyRBAC 历史限制。
			Data: []byte(`{"action": "ALLOW", "policies": {}}`),
		},
		StaticDict: staticDict,
	}
}

// p3DataPkg 按 PackageName 逐层下钻 c.opaData，定位到业务包 map。
func p3DataPkg(t *testing.T, c *Client) map[string]interface{} {
	t.Helper()
	if c.opaData == nil {
		t.Fatalf("opaData is nil")
	}
	cur := c.opaData
	for _, part := range []string{"demo", "example", "v1"} {
		nxt, ok := cur[part].(map[string]interface{})
		if !ok {
			t.Fatalf("opaData[%q] not a map: %+v", part, cur)
		}
		cur = nxt
	}
	return cur
}

func TestInitOPARego_NoStaticDict_NoExtraKeys(t *testing.T) {
	ctx := context.Background()
	c, err := NewClient(ctx, newOPARegoConfig(nil))
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	pkg := p3DataPkg(t, c)
	// 未注入 StaticDict 时三段保留键不应出现
	for _, k := range []string{"services", "rpc_routes", "gateway_routes"} {
		if _, ok := pkg[k]; ok {
			t.Errorf("unexpected key %q in data.<pkg>: %+v", k, pkg)
		}
	}
	// 现有 allow query 仍能 Eval（最小回归）
	rs, err := c.opaRego.Eval(ctx, rego.EvalInput(map[string]any{
		"attributes": map[string]any{
			"request": map[string]any{
				"http": map[string]any{"method": "GET", "path": "/ping"},
			},
		},
		"parsed_path": []string{"ping"},
	}))
	if err != nil {
		t.Fatalf("opaRego.Eval err: %v", err)
	}
	if len(rs) == 0 {
		t.Fatalf("empty result set")
	}
}

func TestInitOPARego_WithStaticDict_InjectsThreeKeys(t *testing.T) {
	ctx := context.Background()
	sd, err := NewStaticDict(p3FixtureFS(t))
	if err != nil {
		t.Fatalf("NewStaticDict err: %v", err)
	}
	if _, ok := sd.Services["demo.v1.example"]; !ok {
		t.Fatalf("fixture sanity: missing demo.v1.example: %+v", sd.Services)
	}

	c, err := NewClient(ctx, newOPARegoConfig(sd))
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	pkg := p3DataPkg(t, c)

	// services: BuildOPAData 直接放原始 Go map（OPA inmem 接受任意类型），
	// 因此这里的断言类型为 map[string]*Service 而非 map[string]any。
	services, ok := pkg["services"].(map[string]*Service)
	if !ok {
		t.Fatalf("services type = %T, want map[string]*Service", pkg["services"])
	}
	svc, ok := services["demo.v1.example"]
	if !ok {
		t.Fatalf("services[demo.v1.example] missing: %+v", services)
	}
	if svc.Code != "demo.v1.example" {
		t.Errorf("svc.Code = %q, want demo.v1.example", svc.Code)
	}

	// rpc_routes
	rpc, ok := pkg["rpc_routes"].(map[string]string)
	if !ok {
		t.Fatalf("rpc_routes type = %T, want map[string]string", pkg["rpc_routes"])
	}
	got := rpc["/grpc_kit.api.example.demo.v1.Demo/ListItems"]
	if want := "demo.v1.example:ListItems"; got != want {
		t.Errorf("rpc_routes[ListItems] = %q, want %q", got, want)
	}

	// gateway_routes
	gws, ok := pkg["gateway_routes"].([]GatewayRoute)
	if !ok {
		t.Fatalf("gateway_routes type = %T, want []GatewayRoute", pkg["gateway_routes"])
	}
	if len(gws) != 2 {
		t.Errorf("len(gateway_routes) = %d, want 2 (ListItems + GetItem)", len(gws))
	}
}

func TestInitOPARego_WithStaticDict_AllowQueryStillWorks(t *testing.T) {
	// 注入 StaticDict 后，原有 data.<pkg>.allow query 行为不应改变（回归）
	ctx := context.Background()
	sd, err := NewStaticDict(p3FixtureFS(t))
	if err != nil {
		t.Fatalf("NewStaticDict err: %v", err)
	}
	c, err := NewClient(ctx, newOPARegoConfig(sd))
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	rs, err := c.opaRego.Eval(ctx, rego.EvalInput(map[string]any{
		"attributes": map[string]any{
			"request": map[string]any{
				"http": map[string]any{"method": "GET", "path": "/ping"},
			},
		},
		"parsed_path": []string{"ping"},
	}))
	if err != nil {
		t.Fatalf("opaRego.Eval err: %v", err)
	}
	if len(rs) == 0 {
		t.Fatalf("empty result set after static dict injection")
	}
}

func TestInitOPARego_StaticDict_CoexistsWithBusinessRBAC(t *testing.T) {
	// 业务 RBAC（合法的 envoy RBAC 字段）与静态字典三段并存于同一 data.<pkg>。
	ctx := context.Background()
	sd, err := NewStaticDict(p3FixtureFS(t))
	if err != nil {
		t.Fatalf("NewStaticDict err: %v", err)
	}
	cfg := &Config{
		PackageName: "demo.example.v1",
		OPARego: &OPARegoConfig{
			Rego: nil,
			// 合法 envoy RBAC JSON：action + policies
			Data: []byte(`{"action": "ALLOW", "policies": {"any": {"permissions": [{"any": true}], "principals": [{"any": true}]}}}`),
		},
		StaticDict: sd,
	}
	c, err := NewClient(ctx, cfg)
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	pkg := p3DataPkg(t, c)

	// 业务侧的 policies / action 应保留
	if _, ok := pkg["action"]; !ok {
		t.Errorf("business 'action' key should be preserved; pkg keys: %v", mapKeys(pkg))
	}
	if _, ok := pkg["policies"]; !ok {
		t.Errorf("business 'policies' key should be preserved; pkg keys: %v", mapKeys(pkg))
	}
	// 静态字典三段也应注入
	for _, k := range []string{"services", "rpc_routes", "gateway_routes"} {
		if _, ok := pkg[k]; !ok {
			t.Errorf("static dict key %q missing from data.<pkg>; pkg keys: %v", k, mapKeys(pkg))
		}
	}
}

// TestBuildOPADataMerge_ReservedKeysOverwrite 直接验证合并语义：
// 静态字典与业务 jsonRBAC 同时存在保留键时，静态字典优先覆盖。
// 不经过 NewClient 以绕过 parseEnvoyRBAC 的 envoy proto 校验。
func TestBuildOPADataMerge_ReservedKeysOverwrite(t *testing.T) {
	sd, err := NewStaticDict(p3FixtureFS(t))
	if err != nil {
		t.Fatalf("NewStaticDict err: %v", err)
	}
	// 模拟 initOPARego 中的合并步骤
	jsonRBAC := map[string]interface{}{
		"services": "BUSINESS_SHOULD_BE_OVERWRITTEN",
		"users":    map[string]interface{}{"admin": []string{"role-admin"}},
	}
	for k, v := range sd.BuildOPAData() {
		jsonRBAC[k] = v
	}
	services, ok := jsonRBAC["services"].(map[string]*Service)
	if !ok {
		t.Fatalf("services overwrite failed; type = %T", jsonRBAC["services"])
	}
	if _, ok := services["demo.v1.example"]; !ok {
		t.Errorf("services should contain demo.v1.example after overwrite, got: %+v", services)
	}
	if _, ok := jsonRBAC["users"].(map[string]interface{}); !ok {
		t.Errorf("non-conflicting business key 'users' should be preserved")
	}
}

// ---------------------------------------------------------------------------
// P6: Client.Allow 接入 input_builder（mergeGrpcKitInput 单测）
// 直接覆盖三类入口 + 旧字段保留回归。
// ---------------------------------------------------------------------------

// p6BuildClient 构造一个最小可用 Client，仅 StaticDict / logger 关键字段填充。
// 不进入 OPA Eval 流程，避免与 P3 测试重复；这里只验证 mergeGrpcKitInput 输入构造。
func p6BuildClient(t *testing.T, sd *StaticDict) *Client {
	t.Helper()
	ctx := context.Background()
	cfg := &Config{
		PackageName: "demo.example.v1",
		StaticDict:  sd,
		// 不配置 OPA*：NewClient 应能正常返回（验证：当前 NewClient 依赖 OPA 任一）。
		// 为避开 OPA 初始化路径，直接走最小 OPARego config。
		OPARego: &OPARegoConfig{Data: []byte(`{"action": "ALLOW", "policies": {}}`)},
	}
	c, err := NewClient(ctx, cfg)
	if err != nil {
		t.Fatalf("NewClient err: %v", err)
	}
	return c
}

// assertGrpcKit 校验 input["grpc_kit"] 的三个字段。
func assertGrpcKit(t *testing.T, input map[string]any, wantSvc, wantAct, wantID string) {
	t.Helper()
	gk, ok := input["grpc_kit"].(map[string]any)
	if !ok {
		t.Fatalf("input.grpc_kit missing or wrong type: %T", input["grpc_kit"])
	}
	if got := gk["service"]; got != wantSvc {
		t.Errorf("grpc_kit.service = %q, want %q", got, wantSvc)
	}
	if got := gk["action"]; got != wantAct {
		t.Errorf("grpc_kit.action = %q, want %q", got, wantAct)
	}
	if got := gk["action_id"]; got != wantID {
		t.Errorf("grpc_kit.action_id = %q, want %q", got, wantID)
	}
	if _, ok := input["subject"].(map[string]any); !ok {
		t.Errorf("input.subject missing or wrong type: %T", input["subject"])
	}
}

func TestAllow_MergeInput_GRPCEntry(t *testing.T) {
	// gRPC 拦截器栈：ctx 含 transport stream，FromGRPCContext 命中 RPCRoutes。
	sd, err := NewStaticDict(p3FixtureFS(t))
	if err != nil {
		t.Fatalf("NewStaticDict err: %v", err)
	}
	c := p6BuildClient(t, sd)

	ctx := newGRPCCtx("/grpc_kit.api.example.demo.v1.Demo/ListItems")
	input := map[string]any{
		"attributes":  map[string]any{"foo": "bar"},  // 旧字段
		"parsed_path": []any{"grpc_kit.api.example.demo.v1.Demo", "ListItems"},
	}
	c.mergeGrpcKitInput(ctx, input, nil)

	assertGrpcKit(t, input, "demo.v1.example", "ListItems", "demo.v1.example:ListItems")

	// 旧字段不应被覆盖
	if attrs, ok := input["attributes"].(map[string]any); !ok || attrs["foo"] != "bar" {
		t.Errorf("legacy attributes mutated: %+v", input["attributes"])
	}
	if pp, ok := input["parsed_path"].([]any); !ok || len(pp) != 2 {
		t.Errorf("legacy parsed_path mutated: %+v", input["parsed_path"])
	}
}

func TestAllow_MergeInput_HTTPEntry_FallsBackToGatewayRoutes(t *testing.T) {
	// 纯 HTTP 入口：ctx 无 grpc.Method，但 envoy req 含 HTTP path。
	// 期望走 GatewayRoutes 字面匹配命中同一个 ActionID。
	sd, err := NewStaticDict(p3FixtureFS(t))
	if err != nil {
		t.Fatalf("NewStaticDict err: %v", err)
	}
	c := p6BuildClient(t, sd)

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/api/v1/items",
				},
			},
		},
	}
	input := map[string]any{}
	c.mergeGrpcKitInput(context.Background(), input, req)

	assertGrpcKit(t, input, "demo.v1.example", "ListItems", "demo.v1.example:ListItems")
}

func TestAllow_MergeInput_HTTPEntry_StripsQueryString(t *testing.T) {
	// envoy path 可能带 querystring，应被截断后再做字面匹配。
	sd, err := NewStaticDict(p3FixtureFS(t))
	if err != nil {
		t.Fatalf("NewStaticDict err: %v", err)
	}
	c := p6BuildClient(t, sd)

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/api/v1/items?limit=10",
				},
			},
		},
	}
	input := map[string]any{}
	c.mergeGrpcKitInput(context.Background(), input, req)

	assertGrpcKit(t, input, "demo.v1.example", "ListItems", "demo.v1.example:ListItems")
}

func TestAllow_MergeInput_GRPCPriorityOverHTTP(t *testing.T) {
	// gRPC 反查命中时不应被 HTTP 兜底覆盖。
	sd, err := NewStaticDict(p3FixtureFS(t))
	if err != nil {
		t.Fatalf("NewStaticDict err: %v", err)
	}
	c := p6BuildClient(t, sd)

	ctx := newGRPCCtx("/grpc_kit.api.example.demo.v1.Demo/GetItem")
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/api/v1/items", // 这是 ListItems 的路径
				},
			},
		},
	}
	input := map[string]any{}
	c.mergeGrpcKitInput(ctx, input, req)

	// 应保留 gRPC 反查结果（GetItem），HTTP 兜底（ListItems）被忽略
	assertGrpcKit(t, input, "demo.v1.example", "GetItem", "demo.v1.example:GetItem")
}

func TestAllow_MergeInput_NoMatch_KeepsEmptyKeys(t *testing.T) {
	// 无 StaticDict / 未注册路径 → grpc_kit 三字段全部空串但键存在。
	c := p6BuildClient(t, nil)

	input := map[string]any{
		"attributes":  map[string]any{"x": 1},
		"parsed_path": []any{"unknown"},
	}
	c.mergeGrpcKitInput(context.Background(), input, nil)

	assertGrpcKit(t, input, "", "", "")
	// 旧字段保留
	if _, ok := input["attributes"]; !ok {
		t.Errorf("legacy attributes lost")
	}
}

func TestAllow_MergeInput_UnregisteredGRPCMethod(t *testing.T) {
	// ctx 有 grpc.Method 但 RPCRoutes 无映射 → 三字段空串。
	sd, err := NewStaticDict(p3FixtureFS(t))
	if err != nil {
		t.Fatalf("NewStaticDict err: %v", err)
	}
	c := p6BuildClient(t, sd)

	ctx := newGRPCCtx("/unknown.svc/UnknownMethod")
	input := map[string]any{}
	c.mergeGrpcKitInput(ctx, input, nil)
	assertGrpcKit(t, input, "", "", "")
}

