package auth

import (
	"strings"
	"testing"
	"testing/fstest"
)

// gatewayYAMLMini 一份最小的 *.gateway.yaml fixture：
//   - 1 个不带 path 变量的 GET 端点 → ResourceSelectors 为空
//   - 1 个 POST + body 端点
//   - 1 个含 `{name}` 单变量的 GET 端点 → 派生 1 个 ResourceSelector
//   - 1 个含 `{name=projects/*/foo/*}` 复合 pattern 的 DELETE 端点
//   - 1 个 additional_bindings 的 GET 端点（同一 selector 多条 path）
const gatewayYAMLMini = `type: google.api.Service
config_version: 3
title: Demo Service

http:
  rules:
  - selector: grpc_kit.api.example.demo.v1.Demo.ListItems
    get: "/api/items"
  - selector: grpc_kit.api.example.demo.v1.Demo.CreateItem
    post: "/api/items"
    body: "*"
  - selector: grpc_kit.api.example.demo.v1.Demo.GetItem
    get: "/api/items/{name}"
  - selector: grpc_kit.api.example.demo.v1.Demo.DeleteItem
    delete: "/api/items/{name=projects/*/items/*}"
  - selector: grpc_kit.api.example.demo.v1.Demo.SearchItems
    get: "/api/items:search"
    additional_bindings:
    - get: "/api/v2/items:search"
`

// swaggerYAMLMini 一份最小的 *.openapiv2.yaml fixture：仅给 ListItems / GetItem 写入 summary/description/tags。
const swaggerYAMLMini = `openapiOptions:
  method:
    - method: "grpc_kit.api.example.demo.v1.Demo.ListItems"
      option:
        summary: "列出所有 Item"
        description: "返回当前账号下的全部 Item"
        tags:
          - "demo"
          - "item"
    - method: "grpc_kit.api.example.demo.v1.Demo.GetItem"
      option:
        summary: "获取 Item 详情"
        tags:
          - "demo"
`

// newMiniAssets 把上面两份 fixture 写到 microservice.{gateway,openapiv2}.yaml 路径下。
func newMiniAssets() fstest.MapFS {
	return fstest.MapFS{
		"openapi/microservice.gateway.yaml":   {Data: []byte(gatewayYAMLMini)},
		"openapi/microservice.openapiv2.yaml": {Data: []byte(swaggerYAMLMini)},
	}
}

// TestNewStaticDict_BasicDerivation 验证 svc_code / action_id / 双向反查表 / OpenAPI 元数据填充。
func TestNewStaticDict_BasicDerivation(t *testing.T) {
	sd, err := NewStaticDict(newMiniAssets())
	if err != nil {
		t.Fatalf("NewStaticDict: %v", err)
	}

	// svc_code = parts[3].parts[4].parts[2] = demo.v1.example
	// （与 pkg/admin/rpc_services.go 现行实现完全一致；详见 §3.2 派生规则）
	const svcCode = "demo.v1.example"
	const grpcSvc = "grpc_kit.api.example.demo.v1.Demo"

	svc, ok := sd.Services[svcCode]
	if !ok {
		t.Fatalf("expected service %q, got %v", svcCode, mapKeys(sd.Services))
	}
	if svc.Code != svcCode {
		t.Errorf("svc.Code = %q, want %q", svc.Code, svcCode)
	}
	if svc.GrpcService != grpcSvc {
		t.Errorf("svc.GrpcService = %q, want %q", svc.GrpcService, grpcSvc)
	}
	if svc.DisplayName != "Demo Service" {
		t.Errorf("svc.DisplayName = %q, want %q", svc.DisplayName, "Demo Service")
	}

	// Actions：应当有 5 个 method
	wantMethods := []string{"ListItems", "CreateItem", "GetItem", "DeleteItem", "SearchItems"}
	if len(svc.Actions) != len(wantMethods) {
		t.Errorf("len(Actions) = %d, want %d (got %v)", len(svc.Actions), len(wantMethods), mapKeys(svc.Actions))
	}
	for _, m := range wantMethods {
		if _, ok := svc.Actions[m]; !ok {
			t.Errorf("missing action %q", m)
		}
	}

	// OpenAPI 元数据填充
	if got := svc.Actions["ListItems"].DisplayName; got != "列出所有 Item" {
		t.Errorf("ListItems.DisplayName = %q", got)
	}
	if got := svc.Actions["ListItems"].Description; got != "返回当前账号下的全部 Item" {
		t.Errorf("ListItems.Description = %q", got)
	}
	if got := strings.Join(svc.Actions["ListItems"].Tags, ","); got != "demo,item" {
		t.Errorf("ListItems.Tags = %q", got)
	}
	if got := svc.Actions["GetItem"].DisplayName; got != "获取 Item 详情" {
		t.Errorf("GetItem.DisplayName = %q", got)
	}
	// 未在 swagger 中出现的方法：DisplayName 留空（不应当 panic）
	if got := svc.Actions["CreateItem"].DisplayName; got != "" {
		t.Errorf("CreateItem.DisplayName should be empty, got %q", got)
	}

	// RPCRoutes 反查表
	rpcKey := "/grpc_kit.api.example.demo.v1.Demo/ListItems"
	if got := sd.RPCRoutes[rpcKey]; got != "demo.v1.example:ListItems" {
		t.Errorf("RPCRoutes[%q] = %q", rpcKey, got)
	}

	// GatewayRoutes：SearchItems 含 additional_bindings → 期望 2 条；总计 1+1+1+1+2 = 6 条
	if got, want := len(sd.GatewayRoutes), 6; got != want {
		t.Errorf("len(GatewayRoutes) = %d, want %d (routes=%+v)", got, want, sd.GatewayRoutes)
	}
	// 校验某条具体记录
	foundSearchV2 := false
	for _, r := range sd.GatewayRoutes {
		if r.PathTemplate == "/api/v2/items:search" && r.Method == "GET" && r.ActionID == "demo.v1.example:SearchItems" {
			foundSearchV2 = true
		}
	}
	if !foundSearchV2 {
		t.Errorf("missing GatewayRoute for SearchItems additional_binding; got %+v", sd.GatewayRoutes)
	}
}

// TestStaticDict_ResourceSelectorPattern 校验 §3.3 / spec/grn.md 中规定的 GRN pattern 格式。
func TestStaticDict_ResourceSelectorPattern(t *testing.T) {
	sd, err := NewStaticDict(newMiniAssets())
	if err != nil {
		t.Fatalf("NewStaticDict: %v", err)
	}

	cases := []struct {
		method      string
		wantCount   int
		wantPattern string // 仅校验第一个 selector
	}{
		// ListItems: 无 path 变量 → 0 个 selector
		{method: "ListItems", wantCount: 0},
		// GetItem: {name} → resourceType=name, pattern=*
		{
			method:      "GetItem",
			wantCount:   1,
			wantPattern: "grn:${partition}:demo.v1.example:${region_code}:${account_id}:name/*",
		},
		// DeleteItem: {name=projects/*/items/*} → pattern=projects/*/items/*
		{
			method:      "DeleteItem",
			wantCount:   1,
			wantPattern: "grn:${partition}:demo.v1.example:${region_code}:${account_id}:name/projects/*/items/*",
		},
	}
	svc := sd.Services["demo.v1.example"]
	for _, tc := range cases {
		act := svc.Actions[tc.method]
		if act == nil {
			t.Errorf("action %s missing", tc.method)
			continue
		}
		if got := len(act.ResourceSelectors); got != tc.wantCount {
			t.Errorf("%s: len(ResourceSelectors) = %d, want %d", tc.method, got, tc.wantCount)
			continue
		}
		if tc.wantCount > 0 && act.ResourceSelectors[0].Pattern != tc.wantPattern {
			t.Errorf("%s: Pattern = %q, want %q", tc.method, act.ResourceSelectors[0].Pattern, tc.wantPattern)
		}
	}
}

// TestNewStaticDict_NoAssets 没有任何 fs 中包含 gateway.yaml 时应当返回 error。
func TestNewStaticDict_NoAssets(t *testing.T) {
	// 完全空的 FS
	_, err := NewStaticDict(fstest.MapFS{})
	if err == nil {
		t.Fatal("expected error when no gateway yaml found, got nil")
	}
	if !strings.Contains(err.Error(), "no gateway yaml") {
		t.Errorf("unexpected error: %v", err)
	}

	// nil 入参
	_, err = NewStaticDict(nil)
	if err == nil {
		t.Fatal("expected error when all assets nil, got nil")
	}
}

// TestNewStaticDict_BadGatewayYAML YAML 损坏时应当返回带文件名的 error。
func TestNewStaticDict_BadGatewayYAML(t *testing.T) {
	bad := fstest.MapFS{
		"openapi/microservice.gateway.yaml": {Data: []byte("not: : valid: yaml: [")},
	}
	_, err := NewStaticDict(bad)
	if err == nil {
		t.Fatal("expected parse error, got nil")
	}
	if !strings.Contains(err.Error(), "microservice.gateway.yaml") {
		t.Errorf("error should name the file, got: %v", err)
	}
}

// TestNewStaticDict_MissingSwaggerOK gateway.yaml 存在但 swagger 缺失：Actions 应当被构造，
// 只是 DisplayName 等元数据为空。
func TestNewStaticDict_MissingSwaggerOK(t *testing.T) {
	assets := fstest.MapFS{
		"openapi/microservice.gateway.yaml": {Data: []byte(gatewayYAMLMini)},
		// 故意不提供 microservice.openapiv2.yaml
	}
	sd, err := NewStaticDict(assets)
	if err != nil {
		t.Fatalf("NewStaticDict: %v", err)
	}
	act := sd.Services["demo.v1.example"].Actions["ListItems"]
	if act == nil {
		t.Fatal("ListItems should be present even without swagger")
	}
	if act.DisplayName != "" || act.Description != "" || len(act.Tags) != 0 {
		t.Errorf("expected empty OpenAPI metadata, got %+v", act)
	}
}

// TestNewStaticDict_MergesMultipleFS 多份 FS 合并：admin + microservice 都派生。
func TestNewStaticDict_MergesMultipleFS(t *testing.T) {
	adminAssets := fstest.MapFS{
		"openapi/admin.gateway.yaml": {Data: []byte(`type: google.api.Service
config_version: 3
title: 公知 Admin
http:
  rules:
  - selector: grpc_kit.api.known.admin.v1.KnownAdmin.CreateAuthLogin
    post: "/builtin/admin/api/v1/auth/login"
    body: "*"
`)},
	}
	sd, err := NewStaticDict(newMiniAssets(), adminAssets)
	if err != nil {
		t.Fatalf("NewStaticDict: %v", err)
	}
	if _, ok := sd.Services["demo.v1.example"]; !ok {
		t.Error("missing demo.v1.example service")
	}
	if _, ok := sd.Services["admin.v1.known"]; !ok {
		t.Errorf("missing admin.v1.known service; got: %v", mapKeys(sd.Services))
	}
	// RPCRoutes 反查应当包含 admin
	if sd.RPCRoutes["/grpc_kit.api.known.admin.v1.KnownAdmin/CreateAuthLogin"] != "admin.v1.known:CreateAuthLogin" {
		t.Errorf("admin RPCRoutes missing or wrong: %v", sd.RPCRoutes)
	}
}

// TestStaticDict_BuildOPAData 输出结构应包含三个顶层 key，且非 nil。
func TestStaticDict_BuildOPAData(t *testing.T) {
	sd, err := NewStaticDict(newMiniAssets())
	if err != nil {
		t.Fatalf("NewStaticDict: %v", err)
	}
	out := sd.BuildOPAData()
	for _, k := range []string{"services", "rpc_routes", "gateway_routes"} {
		if _, ok := out[k]; !ok {
			t.Errorf("BuildOPAData missing key %q (got keys=%v)", k, mapKeys(out))
		}
	}

	// nil-receiver：不应 panic，返回的 map 含 3 个空值
	var nilSD *StaticDict
	out = nilSD.BuildOPAData()
	if _, ok := out["services"]; !ok {
		t.Error("nil-receiver BuildOPAData should still return services key")
	}
}

// TestExtractHTTPPathVariables table-driven 覆盖各种边界 pattern。
func TestExtractHTTPPathVariables(t *testing.T) {
	cases := []struct {
		template string
		want     []pathVariable
	}{
		{template: "", want: nil},
		{template: "/api/items", want: nil},
		{template: "/api/items/{name}", want: []pathVariable{{"name", "*"}}},
		{template: "/api/items/{name=*}", want: []pathVariable{{"name", "*"}}},
		{template: "/api/items/{name=projects/*/items/*}", want: []pathVariable{{"name", "projects/*/items/*"}}},
		{template: "/api/{a}/sub/{b}", want: []pathVariable{{"a", "*"}, {"b", "*"}}},
		// 空变量名应当被跳过
		{template: "/api/{}/x", want: nil},
		// `=` 后为空 → pattern 回退为 "*"
		{template: "/api/{name=}", want: []pathVariable{{"name", "*"}}},
	}
	for _, tc := range cases {
		got := extractHTTPPathVariables(tc.template)
		if len(got) != len(tc.want) {
			t.Errorf("%q: len=%d want %d (got=%+v)", tc.template, len(got), len(tc.want), got)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%q[%d]: got %+v want %+v", tc.template, i, got[i], tc.want[i])
			}
		}
	}
}

// TestAppendPathVariableSelectors_Dedup 同一资源类型+pattern 不应重复追加。
func TestAppendPathVariableSelectors_Dedup(t *testing.T) {
	got := appendPathVariableSelectors("svc.x.api", nil, []string{
		"/a/{name}",
		"/b/{name}", // 同 (resourceType, pattern) — 应当去重
		"/c/{name=projects/*}",
	})
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (selectors=%+v)", len(got), got)
	}
}

// TestHTTPVerb_AllKinds 覆盖 5 个标准 verb + custom。
func TestHTTPVerb_AllKinds(t *testing.T) {
	yaml := `type: google.api.Service
config_version: 3
title: V
http:
  rules:
  - selector: grpc_kit.api.v.s.v1.S.G
    get: "/g"
  - selector: grpc_kit.api.v.s.v1.S.P
    put: "/p"
  - selector: grpc_kit.api.v.s.v1.S.O
    post: "/o"
    body: "*"
  - selector: grpc_kit.api.v.s.v1.S.D
    delete: "/d"
  - selector: grpc_kit.api.v.s.v1.S.A
    patch: "/a"
  - selector: grpc_kit.api.v.s.v1.S.C
    custom:
      kind: "head"
      path: "/c"
`
	sd, err := NewStaticDict(fstest.MapFS{
		"openapi/microservice.gateway.yaml": {Data: []byte(yaml)},
	})
	if err != nil {
		t.Fatalf("NewStaticDict: %v", err)
	}
	want := map[string]string{
		"/g": "GET",
		"/p": "PUT",
		"/o": "POST",
		"/d": "DELETE",
		"/a": "PATCH",
		"/c": "HEAD",
	}
	for _, r := range sd.GatewayRoutes {
		if w, ok := want[r.PathTemplate]; ok && r.Method != w {
			t.Errorf("%s method = %q, want %q", r.PathTemplate, r.Method, w)
		}
	}
	if got := len(sd.GatewayRoutes); got != len(want) {
		t.Errorf("len(GatewayRoutes) = %d, want %d", got, len(want))
	}
}

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
