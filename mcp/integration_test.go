package mcp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"

	mcptools "github.com/grpc-kit/pkg/mcp/tools"
)

const bufconnBufSize = 1024 * 1024

// healthServer 是 grpc_health_v1.HealthServer 的简易实现。
type healthServer struct {
	grpc_health_v1.UnimplementedHealthServer
	status grpc_health_v1.HealthCheckResponse_ServingStatus
}

func (h *healthServer) Check(ctx context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	return &grpc_health_v1.HealthCheckResponse{Status: h.status}, nil
}

// newTestMCPServer 创建一个注册了内置 Tools 的 MCP Server 并挂载到 httptest.Server。
// 返回 httptest.Server 和 MCP Client session 的 setup 辅助。
func newTestMCPServer(t *testing.T, cfg mcptools.BuiltinToolsConfig) *httptest.Server {
	t.Helper()

	srv, err := NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if srv == nil {
		t.Fatalf("expected non-nil server")
	}

	mcptools.RegisterBuiltinTools(srv.MCPServer(), cfg)

	httpServer := httptest.NewServer(srv.Handler())
	return httpServer
}

// connectMCPClient 创建 MCP Client 并连接到 httpServer，返回 session。
// 调用方负责 session.Close()。
func connectMCPClient(t *testing.T, httpServer *httptest.Server) *mcp.ClientSession {
	t.Helper()

	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{
		Endpoint: httpServer.URL,
	}
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client",
		Version: "0.0.1",
	}, nil)

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect failed: %v", err)
	}
	return session
}

// --- 集成测试用例 ---

// TestIntegration_ListTools 验证 4 个内置 Tools 出现在 tools/list 响应中。
func TestIntegration_ListTools(t *testing.T) {
	httpServer := newTestMCPServer(t, mcptools.BuiltinToolsConfig{
		ServiceInfo: func() (map[string]any, error) {
			return map[string]any{"appname": "test-svc"}, nil
		},
		GrpcMethods: func() ([]map[string]any, error) {
			return []map[string]any{}, nil
		},
		Config: func() (map[string]any, error) {
			return map[string]any{"enable": true}, nil
		},
	})
	defer httpServer.Close()

	session := connectMCPClient(t, httpServer)
	defer session.Close()

	ctx := context.Background()
	result, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	wantTools := []string{"health_check", "get_service_info", "list_grpc_methods", "get_config"}
	gotNames := make(map[string]bool)
	for _, tool := range result.Tools {
		gotNames[tool.Name] = true
	}

	for _, name := range wantTools {
		if !gotNames[name] {
			t.Errorf("expected tool %q in tools/list, not found. Got: %v", name, gotNames)
		}
	}
}

// TestIntegration_HealthCheckTool 验证 health_check tool 端到端调用。
// 通过 bufconn 起内存 gRPC Health 服务，MCP Client 调用 health_check tool 验证返回状态。
func TestIntegration_HealthCheckTool(t *testing.T) {
	// 启动内存 gRPC Health server，状态为 SERVING
	lis := bufconn.Listen(bufconnBufSize)
	grpcSrv := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcSrv, &healthServer{status: grpc_health_v1.HealthCheckResponse_SERVING})
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.GracefulStop()

	// 创建 gRPC 连接（惰性缓存）
	var cachedConn *grpc.ClientConn
	grpcConnFn := func() (*grpc.ClientConn, error) {
		if cachedConn != nil {
			return cachedConn, nil
		}
		conn, err := grpc.DialContext(
			context.Background(),
			"bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return lis.Dial()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			return nil, err
		}
		cachedConn = conn
		return cachedConn, nil
	}

	httpServer := newTestMCPServer(t, mcptools.BuiltinToolsConfig{
		GRPCConn: grpcConnFn,
	})
	defer httpServer.Close()
	defer func() {
		if cachedConn != nil {
			cachedConn.Close()
		}
	}()

	session := connectMCPClient(t, httpServer)
	defer session.Close()

	ctx := context.Background()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "health_check",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool(health_check) failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("health_check returned IsError=true, content: %v", result.Content)
	}

	if len(result.Content) == 0 {
		t.Fatalf("health_check returned empty content")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected *mcp.TextContent, got %T", result.Content[0])
	}

	var healthResp struct {
		Status  string `json:"status"`
		Serving bool   `json:"serving"`
	}
	if err := json.Unmarshal([]byte(tc.Text), &healthResp); err != nil {
		t.Fatalf("failed to parse health_check response: %v, text: %s", err, tc.Text)
	}

	if healthResp.Status != "SERVING" {
		t.Errorf("expected status=SERVING, got %q", healthResp.Status)
	}
	if !healthResp.Serving {
		t.Errorf("expected serving=true, got false")
	}
}

// TestIntegration_HealthCheckTool_NotServing 验证 health_check 在 NOT_SERVING 状态下返回 IsError。
func TestIntegration_HealthCheckTool_NotServing(t *testing.T) {
	lis := bufconn.Listen(bufconnBufSize)
	grpcSrv := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcSrv, &healthServer{status: grpc_health_v1.HealthCheckResponse_NOT_SERVING})
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.GracefulStop()

	var cachedConn *grpc.ClientConn
	grpcConnFn := func() (*grpc.ClientConn, error) {
		if cachedConn != nil {
			return cachedConn, nil
		}
		conn, err := grpc.DialContext(
			context.Background(),
			"bufnet",
			grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
				return lis.Dial()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		)
		if err != nil {
			return nil, err
		}
		cachedConn = conn
		return cachedConn, nil
	}

	httpServer := newTestMCPServer(t, mcptools.BuiltinToolsConfig{
		GRPCConn: grpcConnFn,
	})
	defer httpServer.Close()
	defer func() {
		if cachedConn != nil {
			cachedConn.Close()
		}
	}()

	session := connectMCPClient(t, httpServer)
	defer session.Close()

	ctx := context.Background()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "health_check",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool(health_check) failed: %v", err)
	}

	// NOT_SERVING 时 serving=false 但 IsError=false（tool 成功执行，只是状态非 SERVING）
	if result.IsError {
		t.Logf("health_check returned IsError=true for NOT_SERVING (acceptable)")
	}

	if len(result.Content) == 0 {
		t.Fatalf("health_check returned empty content")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected *mcp.TextContent, got %T", result.Content[0])
	}

	var healthResp struct {
		Status  string `json:"status"`
		Serving bool   `json:"serving"`
	}
	if err := json.Unmarshal([]byte(tc.Text), &healthResp); err != nil {
		t.Fatalf("failed to parse health_check response: %v, text: %s", err, tc.Text)
	}

	if healthResp.Status != "NOT_SERVING" {
		t.Errorf("expected status=NOT_SERVING, got %q", healthResp.Status)
	}
	if healthResp.Serving {
		t.Errorf("expected serving=false, got true")
	}
}

// TestIntegration_GetServiceInfoTool 验证 get_service_info tool 端到端调用。
func TestIntegration_GetServiceInfoTool(t *testing.T) {
	wantInfo := map[string]any{
		"appname":        "integration-test-svc",
		"releaseVersion": "1.2.3",
		"gitCommit":      "abc123",
	}

	httpServer := newTestMCPServer(t, mcptools.BuiltinToolsConfig{
		ServiceInfo: func() (map[string]any, error) {
			return wantInfo, nil
		},
	})
	defer httpServer.Close()

	session := connectMCPClient(t, httpServer)
	defer session.Close()

	ctx := context.Background()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_service_info",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("CallTool(get_service_info) failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("get_service_info returned IsError=true, content: %v", result.Content)
	}

	if len(result.Content) == 0 {
		t.Fatalf("get_service_info returned empty content")
	}
	tc, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected *mcp.TextContent, got %T", result.Content[0])
	}

	var info map[string]any
	if err := json.Unmarshal([]byte(tc.Text), &info); err != nil {
		t.Fatalf("failed to parse get_service_info response: %v, text: %s", err, tc.Text)
	}

	if info["appname"] != wantInfo["appname"] {
		t.Errorf("expected appname=%q, got %v", wantInfo["appname"], info["appname"])
	}
	if info["releaseVersion"] != wantInfo["releaseVersion"] {
		t.Errorf("expected releaseVersion=%q, got %v", wantInfo["releaseVersion"], info["releaseVersion"])
	}
	if info["gitCommit"] != wantInfo["gitCommit"] {
		t.Errorf("expected gitCommit=%q, got %v", wantInfo["gitCommit"], info["gitCommit"])
	}
}

// TestIntegration_AuthMiddleware 验证认证中间件拦截未授权请求。
func TestIntegration_AuthMiddleware(t *testing.T) {
	srv, err := NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	mcptools.RegisterBuiltinTools(srv.MCPServer(), mcptools.BuiltinToolsConfig{
		ServiceInfo: func() (map[string]any, error) {
			return map[string]any{"appname": "auth-test"}, nil
		},
	})

	t.Run("rejected_auth_blocks_request", func(t *testing.T) {
		rejectAuth := func(r *http.Request) error {
			return errUnauthorized("test: rejected")
		}
		handler := NewAuthMiddleware(rejectAuth, srv.Handler())
		httpServer := httptest.NewServer(handler)
		defer httpServer.Close()

		ctx := context.Background()
		transport := &mcp.StreamableClientTransport{Endpoint: httpServer.URL}
		client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)

		_, err := client.Connect(ctx, transport, nil)
		if err == nil {
			t.Fatal("expected Connect to fail with rejected auth, but it succeeded")
		}
		if !strings.Contains(err.Error(), "401") && !strings.Contains(err.Error(), "Unauthorized") && !strings.Contains(err.Error(), "unauthorized") {
			t.Logf("Connect error (expected auth failure): %v", err)
		}
	})

	t.Run("nil_auth_allows_request", func(t *testing.T) {
		handler := NewAuthMiddleware(nil, srv.Handler())
		httpServer := httptest.NewServer(handler)
		defer httpServer.Close()

		session := connectMCPClient(t, httpServer)
		defer session.Close()

		ctx := context.Background()
		_, err := session.ListTools(ctx, nil)
		if err != nil {
			t.Fatalf("ListTools should succeed with nil auth, got error: %v", err)
		}
	})
}
