package cfg

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"

	mcpserver "github.com/grpc-kit/pkg/mcp"
	"github.com/grpc-kit/pkg/rpc"
)

// newMCPRuntimeConfig 构造一个 MCP 已启用、adminServer 为 nil 的 LocalConfig，
// 用于测试方案 C（MCP 独立于 adminServer 运行）。
func newMCPRuntimeConfig(t *testing.T) *LocalConfig {
	t.Helper()
	srv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("mcp.NewServer() error: %v", err)
	}
	if srv == nil {
		t.Fatal("mcp.NewServer() returned nil server")
	}

	return &LocalConfig{
		mcpServer: srv,
		logger:    logrus.NewEntry(logrus.New()),
		rpcConfig: &rpc.Config{
			HTTPAddress: "127.0.0.1:18099",
		},
		Services: &ServicesConfig{
			HTTPAddress: "127.0.0.1:18099",
		},
	}
}

// TestHTTPHandlerFrontend_DisabledStillInitializesMCP 验证静态前端开关不会
// 误伤 MCP 的初始化。MCP 是独立能力，关闭 admin/openapi/webroot 托管后，
// 内置 Resource 和 Prompt 仍应在 HTTP Server 启动前完成注册。
func TestHTTPHandlerFrontend_DisabledStillInitializesMCP(t *testing.T) {
	c := newMCPRuntimeConfig(t)
	disabled := false
	c.Frontend = &FrontendConfig{Enable: &disabled}

	if err := c.HTTPHandlerFrontend(http.NewServeMux(), nil); err != nil {
		t.Fatalf("HTTPHandlerFrontend: %v", err)
	}

	session := connectMCPSession(t, c.mcpServer)
	resources, err := session.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	foundVersion := false
	for _, resource := range resources.Resources {
		if resource.Name == "version" {
			foundVersion = true
			break
		}
	}
	if !foundVersion {
		t.Fatal("version resource was not registered while frontend was disabled")
	}

	prompts, err := session.ListPrompts(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	foundGettingStarted := false
	for _, prompt := range prompts.Prompts {
		if prompt.Name == "getting_started" {
			foundGettingStarted = true
			break
		}
	}
	if !foundGettingStarted {
		t.Fatal("getting_started prompt was not registered while frontend was disabled")
	}
}

// connectMCPSession 创建 httptest server 并连接 MCP client session。
func connectMCPSession(t *testing.T, srv *mcpserver.Server) *sdkmcp.ClientSession {
	t.Helper()
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	ctx := context.Background()
	transport := &sdkmcp.StreamableClientTransport{Endpoint: hs.URL}
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

// TestRunAutoBridge_NoAdminServer 验证 adminServer 为 nil 时 runAutoBridge 不 panic、
// 不注册任何 tool（AutoBridge 安全跳过）。
func TestRunAutoBridge_NoAdminServer(t *testing.T) {
	c := newMCPRuntimeConfig(t)

	// adminServer 保持 nil，调用 runAutoBridge 不应 panic
	c.runAutoBridge()

	// 通过 MCP 协议验证：无 tool 注册
	session := connectMCPSession(t, c.mcpServer)
	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools.Tools) != 0 {
		t.Errorf("expected 0 tools (AutoBridge skipped), got %d: %v", len(tools.Tools), toolNames(tools.Tools))
	}
}

// TestRunMCPBuiltinResources_NoAdminServer 验证 adminServer 为 nil 时：
//   - version resource 已注册（不依赖 adminServer）
//   - getting_started prompt 已注册（退化文案，不依赖 adminServer）
//   - microservice resource 未注册（swFS==nil 时跳过）
func TestRunMCPBuiltinResources_NoAdminServer(t *testing.T) {
	c := newMCPRuntimeConfig(t)

	// adminServer 保持 nil，调用 runMCPBuiltinResources 不应 panic
	c.runMCPBuiltinResources()

	session := connectMCPSession(t, c.mcpServer)

	// 验证 version resource 已注册
	res, err := session.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	hasVersion := false
	hasMicroservice := false
	for _, r := range res.Resources {
		switch r.Name {
		case "version":
			hasVersion = true
		case "openapi-microservice":
			hasMicroservice = true
		}
	}
	if !hasVersion {
		t.Error("expected version resource to be registered, but it was not")
	}
	if hasMicroservice {
		t.Error("expected microservice resource to be skipped (no adminServer), but it was registered")
	}

	// 验证 getting_started prompt 已注册
	lr, err := session.ListPrompts(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	hasGettingStarted := false
	for _, p := range lr.Prompts {
		if p.Name == "getting_started" {
			hasGettingStarted = true
		}
	}
	if !hasGettingStarted {
		t.Error("expected getting_started prompt to be registered, but it was not")
	}
}

// toolNames 提取 tool 名称列表用于错误信息。
func toolNames(tools []*sdkmcp.Tool) []string {
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		names = append(names, t.Name)
	}
	return names
}
