package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// registerHealthCheckTool 注册 health_check Tool。
// 若 connFn 为 nil，注册一个返回 "disabled" 的占位 Tool。
func registerHealthCheckTool(server *mcp.Server, connFn GRPCConnFunc) {
	tool := &mcp.Tool{
		Name:        "health_check",
		Description: "Check gRPC server health status via grpc.health.v1.Health/Check",
	}

	mcp.AddTool(server, tool, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		if connFn == nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					&mcp.TextContent{Text: `{"status":"disabled","serving":false}`},
				},
			}, nil, nil
		}

		conn, err := connFn()
		if err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: mustJSON(map[string]string{"error": "failed to connect: " + err.Error()})},
				},
			}, nil, nil
		}
		if conn == nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: mustJSON(map[string]string{"error": "gRPC connection is nil"})},
				},
			}, nil, nil
		}

		client := grpc_health_v1.NewHealthClient(conn)
		resp, err := client.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		if err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: mustJSON(map[string]string{"error": "health check failed: " + err.Error()})},
				},
			}, nil, nil
		}

		status := resp.GetStatus().String()
		serving := resp.GetStatus() == grpc_health_v1.HealthCheckResponse_SERVING
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: mustJSON(map[string]any{"status": status, "serving": serving})},
			},
		}, nil, nil
	})
}
