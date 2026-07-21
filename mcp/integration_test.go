package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/genproto/googleapis/api/serviceconfig"

	mcptools "github.com/grpc-kit/pkg/mcp/tools"
)

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

// TestIntegration_AuthMiddleware 验证认证中间件拦截未授权请求。
//
// 默认内置 Tools 已移除（框架不再注册 health_check 等），此处仅验证中间件行为：
// 拒绝型 authFn 阻断 Connect；nil authFn 放行 ListTools（空 server 返回空 tool 列表）。
func TestIntegration_AuthMiddleware(t *testing.T) {
	srv, err := NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

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

// TestIntegration_AutoBridgeAuthPropagation 端到端验证 AutoBridge 认证透传链路：
// MCP 客户端（携带 Authorization）-> NewAuthMiddleware 包装的 MCP handler
// -> AutoBridge bridgeHandler -> mock gateway（验证收到 Authorization）。
//
// 此测试覆盖真实部署场景：MCP handler 前挂载 NewAuthMiddleware（authFn=nil，
// 即 passthrough 模式），客户端的 Authorization 通过 SDK 的 req.Extra.Header
// 透传到 bridgeHandler，再透传到 gateway。
func TestIntegration_AutoBridgeAuthPropagation(t *testing.T) {
	// mock gateway 记录收到的 Authorization
	var gwAuthHeader string
	gwSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gwAuthHeader = r.Header.Get("Authorization")
		if r.URL.Path != "/v1/items/99" {
			t.Errorf("gateway: expected /v1/items/99, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"99","name":"e2e"}`))
	}))
	defer gwSrv.Close()

	srv, err := NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// 构造 gateway 配置，注册一条 HTTP rule
	gatewayCfg := &serviceconfig.Service{
		Http: &annotations.Http{
			Rules: []*annotations.HttpRule{
				{
					Selector: "grpc_kit.api.test.v1.TestService.GetItem",
					Pattern:  &annotations.HttpRule_Get{Get: "/v1/items/{id}"},
				},
			},
		},
	}

	if err := mcptools.AutoBridge(srv.MCPServer(), nil, &http.Client{}, gwSrv.URL, gatewayCfg, nil, nil, "", nil); err != nil {
		t.Fatalf("AutoBridge failed: %v", err)
	}

	// 用 NewAuthMiddleware 包装（authFn=nil，passthrough 模式）
	handler := NewAuthMiddleware(nil, srv.Handler())
	httpServer := httptest.NewServer(handler)
	defer httpServer.Close()

	ctx := context.Background()
	// 使用自定义 HTTPClient 注入 Authorization header
	transport := &mcp.StreamableClientTransport{
		Endpoint: httpServer.URL,
		HTTPClient: &http.Client{
			Transport: &authInjectingRT{
				base:          http.DefaultTransport,
				authorization: "Bearer e2e-test-token",
			},
		},
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect failed: %v", err)
	}
	defer session.Close()

	result, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "test_service_get_item",
		Arguments: map[string]any{"id": "99"},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result.IsError {
		t.Fatalf("unexpected error: %v", result.Content)
	}

	// 验证 gateway 收到了完整的 Authorization header
	if gwAuthHeader != "Bearer e2e-test-token" {
		t.Errorf("expected gateway to receive 'Bearer e2e-test-token', got %q", gwAuthHeader)
	}
}

// authInjectingRT 是一个 http.RoundTripper 包装器，
// 为所有 outgoing 请求注入指定的 Authorization header。
// 用于集成测试中模拟 MCP 客户端携带认证凭据。
type authInjectingRT struct {
	base          http.RoundTripper
	authorization string
}

func (t *authInjectingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", t.authorization)
	return t.base.RoundTrip(clone)
}
