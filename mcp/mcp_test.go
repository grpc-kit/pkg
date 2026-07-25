package mcp

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestNewServer(t *testing.T) {
	tests := []struct {
		name      string
		enable    bool
		transport string
		wantNil   bool
		wantError bool
	}{
		{
			name:      "Enable=false returns nil",
			enable:    false,
			transport: "streamable_http",
			wantNil:   true,
			wantError: false,
		},
		{
			name:      "streamable_http transport",
			enable:    true,
			transport: "streamable_http",
			wantNil:   false,
			wantError: false,
		},
		{
			name:      "sse transport",
			enable:    true,
			transport: "sse",
			wantNil:   false,
			wantError: false,
		},
		{
			name:      "invalid transport returns error",
			enable:    true,
			transport: "websocket",
			wantNil:   true,
			wantError: true,
		},
		{
			name:      "empty transport returns error",
			enable:    true,
			transport: "",
			wantNil:   true,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, err := NewServer(tt.enable, tt.transport)
			if tt.wantError && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantError && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantNil && srv != nil {
				t.Fatalf("expected nil server, got non-nil")
			}
			if !tt.wantNil && srv == nil {
				t.Fatalf("expected non-nil server, got nil")
			}
			if srv == nil {
				return
			}

			// 验证 Handler() 非 nil
			if srv.Handler() == nil {
				t.Fatalf("Handler() returned nil")
			}

			// 验证 MCPServer() 非 nil
			if srv.MCPServer() == nil {
				t.Fatalf("MCPServer() returned nil")
			}
		})
	}
}

func TestNewServer_Disabled(t *testing.T) {
	srv, err := NewServer(false, "streamable_http")
	if err != nil {
		t.Fatalf("unexpected error for disabled config: %v", err)
	}
	if srv != nil {
		t.Fatalf("expected nil server for disabled config, got non-nil")
	}
}

func TestMCPHandler(t *testing.T) {
	// 创建 MCP Server
	srv, err := NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if srv == nil {
		t.Fatalf("expected non-nil server")
	}

	// 启动 httptest.Server 挂载 MCP handler
	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()

	// 创建 MCP Client 并连接
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
	defer session.Close()

	// 验证 InitializeResult 中的 ServerInfo
	initResult := session.InitializeResult()
	if initResult == nil {
		t.Fatalf("InitializeResult is nil")
	}
	if initResult.ServerInfo == nil {
		t.Fatalf("ServerInfo is nil")
	}
	if initResult.ServerInfo.Name == "" {
		t.Logf("note: ServerInfo.Name is empty (vars.Appname not set at compile time)")
	}
	t.Logf("connected to MCP server: name=%q version=%q protocol=%q",
		initResult.ServerInfo.Name,
		initResult.ServerInfo.Version,
		initResult.ProtocolVersion)
}

// --- Close 方法测试 ---

func TestServerClose_Nil(t *testing.T) {
	// nil Server 不应 panic
	var s *Server
	if err := s.Close(); err != nil {
		t.Fatalf("Close() on nil Server should return nil, got: %v", err)
	}
}

func TestServerClose_NoSessions(t *testing.T) {
	srv, err := NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if srv == nil {
		t.Fatalf("expected non-nil server")
	}

	// 无活跃 session 时 Close 不应报错
	if err := srv.Close(); err != nil {
		t.Fatalf("Close() with no sessions should return nil, got: %v", err)
	}
}

func TestServerClose_WithSessions(t *testing.T) {
	srv, err := NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if srv == nil {
		t.Fatalf("expected non-nil server")
	}

	httpServer := httptest.NewServer(srv.Handler())
	defer httpServer.Close()

	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{
		Endpoint: httpServer.URL,
	}
	client := mcp.NewClient(&mcp.Implementation{
		Name:    "test-client-close",
		Version: "0.0.1",
	}, nil)

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("client.Connect failed: %v", err)
	}
	t.Logf("client connected, session active")

	// 关闭 Server 端所有 sessions
	if err := srv.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}

	// 验证 session 被关闭：客户端后续操作应返回错误
	// 尝试 Ping，预期失败
	pingErr := session.Ping(ctx, nil)
	if pingErr == nil {
		t.Errorf("expected Ping to fail after server Close(), but succeeded")
	} else {
		t.Logf("Ping after Close() returned expected error: %v", pingErr)
	}
}
