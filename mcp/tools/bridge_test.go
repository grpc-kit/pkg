package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grpc-kit/pkg/admin/openapiconfig"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/genproto/googleapis/api/serviceconfig"

	mcpserver "github.com/grpc-kit/pkg/mcp"

	options "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
)

// === 单元测试：辅助函数 ===

func TestToSnakeCase(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"User", "user"},
		{"UserService", "user_service"},
		{"OneopsNetdev", "oneops_netdev"},
		{"DeleteSwitchAdminUser", "delete_switch_admin_user"},
		{"ID", "id"},
		{"HTTPS", "https"},
		{"MyHTTPSService", "my_httpsservice"}, // 连续大写会粘合，符合预期
	}
	for _, tc := range tests {
		got := toSnakeCase(tc.in)
		if got != tc.want {
			t.Errorf("toSnakeCase(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseSelector(t *testing.T) {
	tests := []struct {
		in          string
		wantService string
		wantMethod  string
	}{
		// 7 段：grpc_kit.api.known.admin.v1.KnownAdmin.CreateAuthLogin
		{"grpc_kit.api.known.admin.v1.KnownAdmin.CreateAuthLogin", "KnownAdmin", "CreateAuthLogin"},
		// 6 段：package.api.test.v1.Service.Method
		{"grpc_kit.api.test.v1.TestService.GetItem", "TestService", "GetItem"},
		{"default.api.oneops.netdev.v1.OneopsNetdev.DeleteSwitchAdminUser", "OneopsNetdev", "DeleteSwitchAdminUser"},
		{"", "", ""},
		{"short", "", ""},
		{"a.b.c.d.e", "", ""}, // 5 段，不足
	}
	for _, tc := range tests {
		gotSvc, gotMth := parseSelector(tc.in)
		if gotSvc != tc.wantService || gotMth != tc.wantMethod {
			t.Errorf("parseSelector(%q) = (%q, %q), want (%q, %q)",
				tc.in, gotSvc, gotMth, tc.wantService, tc.wantMethod)
		}
	}
}

func TestHttpRuleMethodAndPath(t *testing.T) {
	tests := []struct {
		name       string
		rule       *annotations.HttpRule
		wantMethod string
		wantPath   string
	}{
		{"nil", nil, "", ""},
		{"GET", &annotations.HttpRule{Pattern: &annotations.HttpRule_Get{Get: "/v1/items"}}, "GET", "/v1/items"},
		{"POST", &annotations.HttpRule{Pattern: &annotations.HttpRule_Post{Post: "/v1/items"}}, "POST", "/v1/items"},
		{"PUT", &annotations.HttpRule{Pattern: &annotations.HttpRule_Put{Put: "/v1/items/{id}"}}, "PUT", "/v1/items/{id}"},
		{"DELETE", &annotations.HttpRule{Pattern: &annotations.HttpRule_Delete{Delete: "/v1/items/{id}"}}, "DELETE", "/v1/items/{id}"},
		{"PATCH", &annotations.HttpRule{Pattern: &annotations.HttpRule_Patch{Patch: "/v1/items/{id}"}}, "PATCH", "/v1/items/{id}"},
		{"Custom", &annotations.HttpRule{Pattern: &annotations.HttpRule_Custom{Custom: &annotations.CustomHttpPattern{Kind: "QUERY", Path: "/v1/search"}}}, "QUERY", "/v1/search"},
		{"empty", &annotations.HttpRule{}, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotM, gotP := httpRuleMethodAndPath(tc.rule)
			if gotM != tc.wantMethod || gotP != tc.wantPath {
				t.Errorf("got (%q, %q), want (%q, %q)", gotM, gotP, tc.wantMethod, tc.wantPath)
			}
		})
	}
}

func TestFormatDescription(t *testing.T) {
	tests := []struct {
		name string
		tags []string
		desc string
		want string
	}{
		{"empty", nil, "no tags here", "no tags here"},
		{"with_tags", []string{"user", "list"}, "list users", "[user, list] list users"},
		{"tags_only", []string{"admin"}, "", "[admin]"},
		{"empty_desc_with_tags", []string{"x", "y"}, " ", "[x, y]  "}, // 描述非空时空格保留
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatDescription(tc.tags, tc.desc)
			if got != tc.want {
				t.Errorf("formatDescription(%v, %q) = %q, want %q", tc.tags, tc.desc, got, tc.want)
			}
		})
	}
}

func TestBuildInputSchema(t *testing.T) {
	tests := []struct {
		tmpl      string
		wantProps bool
		wantName  string
	}{
		{"/v1/items", false, ""},
		{"/v1/items/{id}", true, "id"},
		{"/v1/{a}/{b}/items/{a}", true, "a"}, // 去重
	}
	for _, tc := range tests {
		got := buildInputSchema(tc.tmpl)
		// buildInputSchema 返回 map[string]any
		if got["type"] != "object" {
			t.Errorf("expected type=object, got %v", got["type"])
		}
		if !tc.wantProps {
			if got["properties"] != nil {
				t.Errorf("expected no properties for %q, got %v", tc.tmpl, got["properties"])
			}
			continue
		}
		// 内部嵌套 map 是 map[string]map[string]string
		rawProps, ok := got["properties"].(map[string]map[string]string)
		if !ok {
			t.Fatalf("expected properties map[string]map[string]string, got %T", got["properties"])
		}
		if tc.wantName != "" {
			if _, exists := rawProps[tc.wantName]; !exists {
				t.Errorf("expected property %q in %v", tc.wantName, rawProps)
			}
		}
	}
}

func TestSubstitutePathParams(t *testing.T) {
	args := map[string]json.RawMessage{
		"id":   json.RawMessage(`"123"`),
		"name": json.RawMessage(`"alice"`),
	}
	got, missing := substitutePathParams("/v1/{id}/users/{name}", args)
	if missing != "" {
		t.Errorf("unexpected missing: %s", missing)
	}
	if got != "/v1/123/users/alice" {
		t.Errorf("got %q, want /v1/123/users/alice", got)
	}

	// 缺参数
	_, missing = substitutePathParams("/v1/{id}", map[string]json.RawMessage{})
	if missing != "id" {
		t.Errorf("expected missing=id, got %q", missing)
	}
}

func TestSanitizePathSuffix(t *testing.T) {
	tests := []struct {
		tmpl   string
		method string
		want   string
	}{
		{"/v1/auth/login", "POST", "login"},
		{"/v1/items/{id}", "GET", "items"},
		{"/{a}", "GET", "get"},     // 全是参数时用 method
		{"/v1/foo/", "GET", "foo"}, // 末尾 / 忽略
	}
	for _, tc := range tests {
		got := sanitizePathSuffix(tc.tmpl, tc.method)
		if got != tc.want {
			t.Errorf("sanitizePathSuffix(%q, %q) = %q, want %q", tc.tmpl, tc.method, got, tc.want)
		}
	}
}

// === AutoBridge 集成测试 ===

// makeGatewayCfg 构造一个 serviceconfig.Service 用于测试。
func makeGatewayCfg(rules ...*annotations.HttpRule) *serviceconfig.Service {
	return &serviceconfig.Service{
		Http: &annotations.Http{
			Rules: rules,
		},
	}
}

func TestAutoBridge_NilServer(t *testing.T) {
	// nil server 不应 panic
	err := AutoBridge(nil, nil, nil, "", makeGatewayCfg(), nil, nil)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestAutoBridge_NilConfig(t *testing.T) {
	srv := mcp.NewServer(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	// nil gatewayCfg 不应 panic
	err := AutoBridge(srv, nil, nil, "", nil, nil, nil)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestAutoBridge_NilSwagger(t *testing.T) {
	// swaggerCfg=nil 仍应注册 tool
	mcpSrv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cfg := makeGatewayCfg(
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.GetItem",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items/{id}"},
		},
	)
	if err := AutoBridge(mcpSrv.MCPServer(), nil, http.DefaultClient, "http://localhost:8080", cfg, nil, nil); err != nil {
		t.Fatalf("AutoBridge: %v", err)
	}

	httpServer := httptest.NewServer(mcpSrv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	// 注册的 toolName: test_service_get_item (snake_case 拼接)
	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools.Tools) == 0 {
		t.Fatalf("expected at least 1 tool, got 0")
	}
}

func TestAutoBridge_ToolRegistration(t *testing.T) {
	mcpSrv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// swagger: 两个方法都有 description 和 tags
	swagger := &openapiconfig.OpenAPIConfig{
		OpenapiOptions: &openapiconfig.OpenAPIOptions{
			Method: []*openapiconfig.OpenAPIMethodOption{
				{
					Method: "grpc_kit.api.test.v1.TestService.GetItem",
				},
				{
					Method: "grpc_kit.api.test.v1.TestService.ListItems",
				},
			},
		},
	}

	cfg := makeGatewayCfg(
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.GetItem",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items/{id}"},
		},
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.ListItems",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items"},
		},
	)

	if err := AutoBridge(mcpSrv.MCPServer(), nil, http.DefaultClient, "http://localhost:8080", cfg, swagger, nil); err != nil {
		t.Fatalf("AutoBridge: %v", err)
	}

	httpServer := httptest.NewServer(mcpSrv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	// 期望至少注册 2 个 tool：test_service_get_item, test_service_list_items
	names := make(map[string]bool, len(tools.Tools))
	for _, tool := range tools.Tools {
		names[tool.Name] = true
	}
	if !names["test_service_get_item"] {
		t.Errorf("expected tool test_service_get_item, got: %v", names)
	}
	if !names["test_service_list_items"] {
		t.Errorf("expected tool test_service_list_items, got: %v", names)
	}
}

func TestAutoBridge_AdditionalBindings(t *testing.T) {
	mcpSrv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// 一个 rule 含 1 primary + 1 additional binding
	rule := &annotations.HttpRule{
		Selector: "grpc_kit.api.test.v1.TestService.GetItem",
		Pattern:  &annotations.HttpRule_Get{Get: "/v1/items/{id}"},
		AdditionalBindings: []*annotations.HttpRule{
			{Pattern: &annotations.HttpRule_Get{Get: "/api/items/{id}"}},
		},
	}

	cfg := makeGatewayCfg(rule)
	if err := AutoBridge(mcpSrv.MCPServer(), nil, http.DefaultClient, "http://localhost:8080", cfg, nil, nil); err != nil {
		t.Fatalf("AutoBridge: %v", err)
	}

	httpServer := httptest.NewServer(mcpSrv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	// 应注册 2 个 tool：baseName 和 baseName + api suffix
	names := make([]string, 0)
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	if len(names) != 2 {
		t.Fatalf("expected 2 tools (primary + additional), got %d: %v", len(names), names)
	}

	// 第一个不带后缀（baseName），第二个带 "__items" 后缀
	hasBase, hasSuffixed := false, false
	for _, n := range names {
		if n == "test_service_get_item" {
			hasBase = true
		}
		if strings.HasPrefix(n, "test_service_get_item__") {
			hasSuffixed = true
		}
	}
	if !hasBase {
		t.Errorf("expected test_service_get_item (primary), got %v", names)
	}
	if !hasSuffixed {
		t.Errorf("expected suffixed tool (additional binding), got %v", names)
	}
}

func TestAutoBridge_ToolCall(t *testing.T) {
	// mock HTTP server 模拟 gateway
	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 验证 path 参数已替换
		if r.URL.Path != "/v1/items/42" {
			t.Errorf("expected /v1/items/42, got %s", r.URL.Path)
		}
		// 验证 Authorization header 已透传到 gateway
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("gateway: expected Authorization 'Bearer test-token', got %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"42","name":"alice"}`))
	}))
	defer gwSrv.Close()

	mcpSrv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cfg := makeGatewayCfg(
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.GetItem",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items/{id}"},
		},
	)

	if err := AutoBridge(mcpSrv.MCPServer(), nil, &http.Client{}, gwSrv.URL, cfg, nil, nil); err != nil {
		t.Fatalf("AutoBridge: %v", err)
	}

	httpServer := httptest.NewServer(mcpSrv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	// 使用自定义 HTTPClient，通过 RoundTripper 为每个 MCP POST 请求注入 Authorization header，
	// 模拟真实 MCP 客户端携带认证凭据的场景。
	transport := &mcp.StreamableClientTransport{
		Endpoint: httpServer.URL,
		HTTPClient: &http.Client{
			Transport: &authInjectingTransport{
				base:           http.DefaultTransport,
				authorization:  "Bearer test-token",
				targetEndpoint: httpServer.URL,
			},
		},
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	// 调用 tool，传入 path 参数
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "test_service_get_item",
		Arguments: map[string]any{"id": "42"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}
	if len(result.Content) == 0 {
		t.Fatalf("empty result")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected TextContent, got %T", result.Content[0])
	}
	if !strings.Contains(tc.Text, `"id":"42"`) {
		t.Errorf("unexpected response body: %s", tc.Text)
	}
}

// authInjectingTransport 是一个 http.RoundTripper 包装器，
// 为发往 targetEndpoint 的请求注入指定的 Authorization header。
// 用于测试 MCP 客户端携带认证凭据时 AutoBridge 的透传行为。
type authInjectingTransport struct {
	base           http.RoundTripper
	authorization  string
	targetEndpoint string
}

func (t *authInjectingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 仅对发往 MCP server 的请求注入 Authorization（不干扰 gateway 的 mock 请求）
	if req.URL.Host == "" || strings.Contains(t.targetEndpoint, req.URL.Host) {
		// 克隆请求以避免修改原始请求
		clone := req.Clone(req.Context())
		clone.Header.Set("Authorization", t.authorization)
		return t.base.RoundTrip(clone)
	}
	return t.base.RoundTrip(req)
}

func TestAutoBridge_ToolCallError(t *testing.T) {
	// mock gateway 返回 500
	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal"}`))
	}))
	defer gwSrv.Close()

	mcpSrv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cfg := makeGatewayCfg(
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.GetItem",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items/{id}"},
		},
	)

	if err := AutoBridge(mcpSrv.MCPServer(), nil, &http.Client{}, gwSrv.URL, cfg, nil, nil); err != nil {
		t.Fatalf("AutoBridge: %v", err)
	}

	httpServer := httptest.NewServer(mcpSrv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "test_service_get_item",
		Arguments: map[string]any{"id": "1"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Errorf("expected IsError=true, got false; content: %v", result.Content)
	}
}

func TestAutoBridge_ToolCallMissingPathParam(t *testing.T) {
	mcpSrv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cfg := makeGatewayCfg(
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.GetItem",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items/{id}"},
		},
	)

	if err := AutoBridge(mcpSrv.MCPServer(), nil, &http.Client{}, "http://localhost", cfg, nil, nil); err != nil {
		t.Fatalf("AutoBridge: %v", err)
	}

	httpServer := httptest.NewServer(mcpSrv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	// 缺 id 参数
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "test_service_get_item",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Errorf("expected IsError=true for missing path param, got false; content: %v", result.Content)
	}
	if len(result.Content) > 0 {
		tc, ok := result.Content[0].(*mcp.TextContent)
		if ok && !strings.Contains(tc.Text, "id") {
			t.Errorf("expected error to mention 'id', got: %s", tc.Text)
		}
	}
}

// TestAutoBridge_AuthPropagation 验证 MCP 客户端携带 Authorization header 时，
// AutoBridge 的 bridgeHandler 能通过 req.Extra.Header 获取并透传给 gateway。
// 这是 stateful 模式下的核心认证透传路径。
func TestAutoBridge_AuthPropagation(t *testing.T) {
	// mock gateway 记录收到的 Authorization
	var gwAuthHeader string
	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gwAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","name":"ok"}`))
	}))
	defer gwSrv.Close()

	mcpSrv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cfg := makeGatewayCfg(
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.GetItem",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items/{id}"},
		},
	)

	if err := AutoBridge(mcpSrv.MCPServer(), nil, &http.Client{}, gwSrv.URL, cfg, nil, nil); err != nil {
		t.Fatalf("AutoBridge: %v", err)
	}

	httpServer := httptest.NewServer(mcpSrv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{
		Endpoint: httpServer.URL,
		HTTPClient: &http.Client{
			Transport: &authInjectingTransport{
				base:           http.DefaultTransport,
				authorization:  "Bearer propagation-test",
				targetEndpoint: httpServer.URL,
			},
		},
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "test_service_get_item",
		Arguments: map[string]any{"id": "1"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	// 验证 gateway 收到了完整的 Authorization header
	if gwAuthHeader != "Bearer propagation-test" {
		t.Errorf("expected gateway to receive Authorization 'Bearer propagation-test', got %q", gwAuthHeader)
	}
}

// TestAutoBridge_AuthPropagation_NoAuth 验证 MCP 客户端不携带 Authorization header 时，
// bridgeHandler 不会设置空值或 panic，gateway 收到的 Authorization 为空。
func TestAutoBridge_AuthPropagation_NoAuth(t *testing.T) {
	// mock gateway 记录收到的 Authorization
	var gwAuthHeader string
	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gwAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"1","name":"ok"}`))
	}))
	defer gwSrv.Close()

	mcpSrv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cfg := makeGatewayCfg(
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.GetItem",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items/{id}"},
		},
	)

	if err := AutoBridge(mcpSrv.MCPServer(), nil, &http.Client{}, gwSrv.URL, cfg, nil, nil); err != nil {
		t.Fatalf("AutoBridge: %v", err)
	}

	httpServer := httptest.NewServer(mcpSrv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	// 不注入 Authorization 的标准 transport
	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "test_service_get_item",
		Arguments: map[string]any{"id": "1"},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	// 验证 gateway 未收到 Authorization
	if gwAuthHeader != "" {
		t.Errorf("expected empty Authorization at gateway, got %q", gwAuthHeader)
	}
}

// makeSwaggerWithTags 构造一个带 tags 的 OpenAPIConfig 用于 tag 过滤测试。
// methodTags: key=method selector, value=tags 列表。
func makeSwaggerWithTags(methodTags map[string][]string) *openapiconfig.OpenAPIConfig {
	cfg := &openapiconfig.OpenAPIConfig{
		OpenapiOptions: &openapiconfig.OpenAPIOptions{
			Method: make([]*openapiconfig.OpenAPIMethodOption, 0, len(methodTags)),
		},
	}
	for method, tags := range methodTags {
		cfg.OpenapiOptions.Method = append(cfg.OpenapiOptions.Method, &openapiconfig.OpenAPIMethodOption{
			Method: method,
			Option: &options.Operation{Tags: tags},
		})
	}
	return cfg
}

// TestAutoBridge_TagFilter_Whitelist 验证 allowedTags 非空时，
// 只有 tags 命中白名单的方法才注册为 MCP tool。
func TestAutoBridge_TagFilter_Whitelist(t *testing.T) {
	mcpSrv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cfg := makeGatewayCfg(
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.GetItem",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items/{id}"},
		},
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.ListItems",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items"},
		},
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.DeleteItem",
			Pattern:  &annotations.HttpRule_Delete{Delete: "/v1/items/{id}"},
		},
	)

	// GetItem 有 mcp tag，ListItems 只有 admin tag，DeleteItem 无 tags
	swagger := makeSwaggerWithTags(map[string][]string{
		"grpc_kit.api.test.v1.TestService.GetItem":    {"mcp"},
		"grpc_kit.api.test.v1.TestService.ListItems":  {"admin"},
		"grpc_kit.api.test.v1.TestService.DeleteItem": {},
	})

	if err := AutoBridge(mcpSrv.MCPServer(), nil, http.DefaultClient, "http://localhost:8080", cfg, swagger, []string{"mcp"}); err != nil {
		t.Fatalf("AutoBridge: %v", err)
	}

	httpServer := httptest.NewServer(mcpSrv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	// 仅 GetItem（tag=mcp）应被注册
	if len(tools.Tools) != 1 {
		t.Fatalf("expected 1 tool (only mcp-tagged), got %d: %+v", len(tools.Tools), tools.Tools)
	}
	if tools.Tools[0].Name != "test_service_get_item" {
		t.Errorf("expected tool name 'test_service_get_item', got %q", tools.Tools[0].Name)
	}
}

// TestAutoBridge_TagFilter_EmptyWhitelist 验证 allowedTags 为空时不过滤（向后兼容）。
func TestAutoBridge_TagFilter_EmptyWhitelist(t *testing.T) {
	mcpSrv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cfg := makeGatewayCfg(
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.GetItem",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items/{id}"},
		},
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.ListItems",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items"},
		},
	)

	swagger := makeSwaggerWithTags(map[string][]string{
		"grpc_kit.api.test.v1.TestService.GetItem":   {"mcp"},
		"grpc_kit.api.test.v1.TestService.ListItems": {"admin"},
	})

	// allowedTags=nil => 不过滤，全部注册
	if err := AutoBridge(mcpSrv.MCPServer(), nil, http.DefaultClient, "http://localhost:8080", cfg, swagger, nil); err != nil {
		t.Fatalf("AutoBridge: %v", err)
	}

	httpServer := httptest.NewServer(mcpSrv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	if len(tools.Tools) != 2 {
		t.Fatalf("expected 2 tools (no filtering), got %d", len(tools.Tools))
	}
}

// TestAutoBridge_TagFilter_NilSwagger 验证 allowedTags 非空但 swaggerCfg=nil 时，
// 所有方法都无 tags 信息，因此全部被过滤（不注册任何 tool）。
func TestAutoBridge_TagFilter_NilSwagger(t *testing.T) {
	mcpSrv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cfg := makeGatewayCfg(
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.GetItem",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items/{id}"},
		},
	)

	// swaggerCfg=nil + allowedTags=["mcp"] => 无法确定 tags => 全部被过滤
	if err := AutoBridge(mcpSrv.MCPServer(), nil, http.DefaultClient, "http://localhost:8080", cfg, nil, []string{"mcp"}); err != nil {
		t.Fatalf("AutoBridge: %v", err)
	}

	httpServer := httptest.NewServer(mcpSrv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	if len(tools.Tools) != 0 {
		t.Fatalf("expected 0 tools (nil swagger + non-empty allowedTags), got %d", len(tools.Tools))
	}
}

// TestAutoBridge_TagFilter_MultipleAllowedTags 验证 OR 语义：
// operation tags 命中白名单中任一值即注册。
func TestAutoBridge_TagFilter_MultipleAllowedTags(t *testing.T) {
	mcpSrv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	cfg := makeGatewayCfg(
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.GetItem",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items/{id}"},
		},
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.ListItems",
			Pattern:  &annotations.HttpRule_Get{Get: "/v1/items"},
		},
		&annotations.HttpRule{
			Selector: "grpc_kit.api.test.v1.TestService.DeleteItem",
			Pattern:  &annotations.HttpRule_Delete{Delete: "/v1/items/{id}"},
		},
	)

	swagger := makeSwaggerWithTags(map[string][]string{
		"grpc_kit.api.test.v1.TestService.GetItem":    {"mcp"},
		"grpc_kit.api.test.v1.TestService.ListItems":  {"admin"},
		"grpc_kit.api.test.v1.TestService.DeleteItem": {"internal"},
	})

	// allowedTags=["mcp", "admin"] => GetItem(mcp) 和 ListItems(admin) 命中
	if err := AutoBridge(mcpSrv.MCPServer(), nil, http.DefaultClient, "http://localhost:8080", cfg, swagger, []string{"mcp", "admin"}); err != nil {
		t.Fatalf("AutoBridge: %v", err)
	}

	httpServer := httptest.NewServer(mcpSrv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	if len(tools.Tools) != 2 {
		t.Fatalf("expected 2 tools (mcp + admin tagged), got %d", len(tools.Tools))
	}

	names := make(map[string]struct{}, len(tools.Tools))
	for _, tl := range tools.Tools {
		names[tl.Name] = struct{}{}
	}
	if _, ok := names["test_service_get_item"]; !ok {
		t.Error("expected tool 'test_service_get_item' to be registered")
	}
	if _, ok := names["test_service_list_items"]; !ok {
		t.Error("expected tool 'test_service_list_items' to be registered")
	}
	if _, ok := names["test_service_delete_item"]; ok {
		t.Error("tool 'test_service_delete_item' should NOT be registered (tag=internal not in whitelist)")
	}
}
