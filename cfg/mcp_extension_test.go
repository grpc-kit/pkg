package cfg

import (
	"testing"

	"github.com/grpc-kit/pkg/mcp"
)

// TestMCPServerInstance_Disabled 验证 MCP 未启用时 getter 返回 nil。
func TestMCPServerInstance_Disabled(t *testing.T) {
	c := &LocalConfig{
		AIConnector: &AIConnectorConfig{
			Enable: false,
			MCPServer: MCPServerConfig{
				Enable: false,
			},
		},
	}
	if err := c.initAIConnector(); err != nil {
		t.Fatalf("initAIConnector() error: %v", err)
	}
	// registerGateway 在 AIConnector.MCPServer.Enable=false 时不会创建 mcpServer
	if got := c.MCPServerInstance(); got != nil {
		t.Errorf("MCPServerInstance() = %v, want nil (mcp disabled)", got)
	}
}

// TestMCPServerInstance_BeforeRegister 验证即使 MCP 已启用（initAIConnector 已填充默认值），
// 但尚未调用 Register/registerGateway 时，mcpServer 仍为 nil，getter 返回 nil。
func TestMCPServerInstance_BeforeRegister(t *testing.T) {
	c := &LocalConfig{
		AIConnector: &AIConnectorConfig{
			Enable: true,
			MCPServer: MCPServerConfig{
				Enable:    true,
				Transport: "streamable_http",
				Path:      "/mcp",
			},
		},
	}
	if err := c.initAIConnector(); err != nil {
		t.Fatalf("initAIConnector() error: %v", err)
	}
	// Enable=true 但 registerGateway 未执行，mcpServer 仍为 nil
	if got := c.MCPServerInstance(); got != nil {
		t.Errorf("MCPServerInstance() = %v, want nil (Register not called yet)", got)
	}
}

// TestMCPServerInstance_Enabled 验证 mcpServer 创建后 getter 返回非 nil 的 wrapper，
// 且 wrapper.MCPServer() 可取得 SDK 实例。
//
// 说明：完整的 registerGateway 需要拉起 gRPC listener、加载 adminServer gateway YAML
// 并通过 getClientCredentials（未配置 TLS 时方可）等较重引导，不适合在 cfg 包单元测试中
// 直接调用。此处复用 registerGateway 内部创建 mcpServer 的同一路径（mcp.NewServer，
// 见 grpc_server.go 的 registerGateway），直接赋值后验证 getter 契约。
// registerGateway -> c.mcpServer 的赋值 wiring 由源码 grpc_server.go 保证。
func TestMCPServerInstance_Enabled(t *testing.T) {
	c := &LocalConfig{
		AIConnector: &AIConnectorConfig{
			Enable: true,
			MCPServer: MCPServerConfig{
				Enable:    true,
				Transport: "streamable_http",
				Path:      "/mcp",
			},
		},
	}
	if err := c.initAIConnector(); err != nil {
		t.Fatalf("initAIConnector() error: %v", err)
	}

	// 模拟 registerGateway 中创建并赋值 mcpServer 的路径（grpc_server.go registerGateway）
	srv, err := mcp.NewServer(c.AIConnector.MCPServer.Enable, c.AIConnector.MCPServer.Transport)
	if err != nil {
		t.Fatalf("mcp.NewServer() error: %v", err)
	}
	if srv == nil {
		t.Fatal("mcp.NewServer() returned nil server")
	}
	c.mcpServer = srv

	got := c.MCPServerInstance()
	if got == nil {
		t.Fatal("MCPServerInstance() returned nil after mcpServer set")
	}
	if got != srv {
		t.Error("MCPServerInstance() did not return the same wrapper instance that was set")
	}
	if got.MCPServer() == nil {
		t.Error("MCPServerInstance().MCPServer() is nil; expected non-nil SDK server")
	}
}
