package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"

	mcpserver "github.com/grpc-kit/pkg/mcp"
)

// --- Mock 回调函数 ---

func mockGRPCConnFn() (*grpc.ClientConn, error) {
	// 返回 nil, err 表示连接不可用；测试 health_check error 场景
	return nil, fmt.Errorf("connection disabled in test")
}

func mockServiceInfoFn() (map[string]any, error) {
	return map[string]any{
		"appname":        "test-service",
		"releaseVersion": "1.0.0",
		"gitCommit":      "abc123",
	}, nil
}

func mockGrpcMethodsFn() ([]map[string]any, error) {
	return []map[string]any{
		{
			"code":        "ListUsers",
			"grpcMethod":  "/api.v1.UserService/ListUsers",
			"displayName": "List Users",
			"description": "List all users",
			"tags":        []string{"user", "list"},
		},
		{
			"code":        "GetUser",
			"grpcMethod":  "/api.v1.UserService/GetUser",
			"displayName": "Get User",
			"description": "Get a single user",
			"tags":        []string{"user", "get"},
		},
	}, nil
}

func mockConfigFn() (map[string]any, error) {
	return map[string]any{
		"services": map[string]any{
			"grpcListenPort": 9080,
		},
		"security": map[string]any{
			"password": "******",
		},
	}, nil
}

// --- 辅助函数 ---

// setupTestServer 创建一个挂载了内置 Tools 的 MCP Server + httptest.Server + 已连接的 ClientSession。
func setupTestServer(t *testing.T, cfg BuiltinToolsConfig) (*mcp.ClientSession, *httptest.Server) {
	t.Helper()

	srv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if srv == nil {
		t.Fatalf("expected non-nil server")
	}

	RegisterBuiltinTools(srv.MCPServer(), cfg)

	httpServer := httptest.NewServer(srv.Handler())
	t.Cleanup(httpServer.Close)

	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "0.0.1",
	}, nil)

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect failed: %v", err)
	}
	t.Cleanup(func() { session.Close() })

	return session, httpServer
}

// callTool 调用指定 Tool 并返回 TextContent 的文本内容。
func callTool(t *testing.T, session *mcp.ClientSession, name string) string {
	t.Helper()
	ctx := context.Background()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name})
	if err != nil {
		t.Fatalf("CallTool(%q) failed: %v", name, err)
	}
	if result == nil || len(result.Content) == 0 {
		t.Fatalf("CallTool(%q) returned empty result", name)
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("CallTool(%q) first content is not TextContent, got %T", name, result.Content[0])
	}
	return tc.Text
}

// --- 测试用例 ---

func TestRegisterBuiltinTools_NilServer(t *testing.T) {
	// 不应 panic
	RegisterBuiltinTools(nil, BuiltinToolsConfig{})
}

func TestRegisterBuiltinTools_AllNilCallbacks(t *testing.T) {
	// 所有回调为 nil，health_check 仍应注册（返回 disabled）
	session, _ := setupTestServer(t, BuiltinToolsConfig{})

	ctx := context.Background()
	result, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	// health_check 总是注册
	var foundHealth bool
	for _, tool := range result.Tools {
		if tool.Name == "health_check" {
			foundHealth = true
		}
	}
	if !foundHealth {
		t.Fatalf("health_check tool not found in tools/list")
	}

	// 调用 health_check 应返回 disabled
	text := callTool(t, session, "health_check")
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("failed to unmarshal health_check result: %v\nraw: %s", err, text)
	}
	if m["status"] != "disabled" {
		t.Fatalf("expected status=disabled, got %v", m["status"])
	}
}

func TestHealthCheckTool_ConnectionError(t *testing.T) {
	session, _ := setupTestServer(t, BuiltinToolsConfig{
		GRPCConn: mockGRPCConnFn,
	})

	text := callTool(t, session, "health_check")
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("failed to unmarshal: %v\nraw: %s", err, text)
	}
	if m["error"] == nil {
		t.Fatalf("expected error field, got: %s", text)
	}
}

func TestServiceInfoTool(t *testing.T) {
	session, _ := setupTestServer(t, BuiltinToolsConfig{
		ServiceInfo: mockServiceInfoFn,
	})

	text := callTool(t, session, "get_service_info")
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("failed to unmarshal: %v\nraw: %s", err, text)
	}
	if m["appname"] != "test-service" {
		t.Fatalf("expected appname=test-service, got %v", m["appname"])
	}
	if m["releaseVersion"] != "1.0.0" {
		t.Fatalf("expected releaseVersion=1.0.0, got %v", m["releaseVersion"])
	}
}

func TestGrpcMethodsTool(t *testing.T) {
	session, _ := setupTestServer(t, BuiltinToolsConfig{
		GrpcMethods: mockGrpcMethodsFn,
	})

	text := callTool(t, session, "list_grpc_methods")
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("failed to unmarshal: %v\nraw: %s", err, text)
	}

	methods, ok := m["methods"].([]any)
	if !ok {
		t.Fatalf("expected methods to be []any, got %T", m["methods"])
	}
	if len(methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(methods))
	}
	if total, ok := m["total"].(float64); !ok || total != 2 {
		t.Fatalf("expected total=2, got %v", m["total"])
	}

	first := methods[0].(map[string]any)
	if first["grpcMethod"] != "/api.v1.UserService/ListUsers" {
		t.Fatalf("unexpected grpcMethod: %v", first["grpcMethod"])
	}
}

func TestConfigTool(t *testing.T) {
	session, _ := setupTestServer(t, BuiltinToolsConfig{
		Config: mockConfigFn,
	})

	text := callTool(t, session, "get_config")
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("failed to unmarshal: %v\nraw: %s", err, text)
	}

	security, ok := m["security"].(map[string]any)
	if !ok {
		t.Fatalf("expected security to be map[string]any, got %T", m["security"])
	}
	if security["password"] != "******" {
		t.Fatalf("expected password=******, got %v", security["password"])
	}
}

func TestRegisterBuiltinTools_AllRegistered(t *testing.T) {
	session, _ := setupTestServer(t, BuiltinToolsConfig{
		GRPCConn:    mockGRPCConnFn,
		ServiceInfo: mockServiceInfoFn,
		GrpcMethods: mockGrpcMethodsFn,
		Config:      mockConfigFn,
	})

	ctx := context.Background()
	result, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	wantTools := map[string]bool{
		"health_check":      false,
		"get_service_info":  false,
		"list_grpc_methods": false,
		"get_config":        false,
	}
	for _, tool := range result.Tools {
		if _, ok := wantTools[tool.Name]; ok {
			wantTools[tool.Name] = true
		}
	}

	for name, found := range wantTools {
		if !found {
			t.Errorf("tool %q not found in tools/list", name)
		}
	}
}
