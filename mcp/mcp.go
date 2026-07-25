package mcp

import (
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/grpc-kit/pkg/vars"
)

// Server 封装 MCP Server 及其 HTTP handler
type Server struct {
	mcpServer *mcp.Server
	handler   http.Handler
}

// NewServer 根据 MCP 配置参数创建 MCP Server
// 若 enable 为 false，返回 nil, nil
func NewServer(enable bool, transport string) (*Server, error) {
	if !enable {
		return nil, nil
	}

	// 获取带默认值的版本信息（ReleaseVersion 默认 "0.0.0"）
	v := vars.GetVersion()

	// 创建 MCP Implementation（Name 可能为空，SDK 不 panic）
	impl := &mcp.Implementation{
		Name:    v.Appname,
		Version: v.ReleaseVersion,
	}

	// 创建 MCP Server（impl 不可 nil，options 传 nil 用默认值）
	mcpServer := mcp.NewServer(impl, nil)

	// getServer 回调：每个请求返回同一个 MCP Server 实例
	getServer := func(_ *http.Request) *mcp.Server {
		return mcpServer
	}

	// 根据传输协议创建对应的 HTTP handler
	var handler http.Handler
	switch transport {
	case "streamable_http":
		handler = mcp.NewStreamableHTTPHandler(getServer, &mcp.StreamableHTTPOptions{
			JSONResponse:               false,
			DisableLocalhostProtection: true,
		})
	case "sse":
		handler = mcp.NewSSEHandler(getServer, nil)
	default:
		return nil, fmt.Errorf("unsupported MCP transport: %s (supported: streamable_http, sse)", transport)
	}

	return &Server{
		mcpServer: mcpServer,
		handler:   handler,
	}, nil
}

// Handler 返回 MCP Server 的 HTTP handler
func (s *Server) Handler() http.Handler {
	return s.handler
}

// MCPServer 返回底层 MCP Server 实例，供后续注册 Tools 使用
func (s *Server) MCPServer() *mcp.Server {
	return s.mcpServer
}

// Close 优雅关闭 MCP Server 的所有活跃 sessions
// 采用 best-effort 策略：遍历所有活跃 session 逐个关闭，收集第一个错误但继续关闭剩余 session。
// SDK handler 无导出的 Close 方法，关闭 session 后 HTTP 连接会自然终止。
func (s *Server) Close() error {
	if s == nil || s.mcpServer == nil {
		return nil
	}

	var firstErr error
	for session := range s.mcpServer.Sessions() {
		if err := session.Close(); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
