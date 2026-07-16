package mcp

import (
	"context"
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerGrpcMethodsTool 注册 list_grpc_methods Tool。
// 若 methodsFn 为 nil，跳过注册。
func registerGrpcMethodsTool(server *mcp.Server, methodsFn GrpcMethodsFunc) {
	if methodsFn == nil {
		return
	}

	tool := &mcp.Tool{
		Name:        "list_grpc_methods",
		Description: "List all registered gRPC methods with their HTTP mappings and descriptions",
	}

	mcp.AddTool(server, tool, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		methods, err := methodsFn()
		if err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: mustJSON(map[string]string{"error": err.Error()})},
				},
			}, nil, nil
		}

		result := map[string]any{
			"methods": methods,
			"total":   len(methods),
		}

		b, err := json.Marshal(result)
		if err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: `{"error":"json marshal failed"}`},
				},
			}, nil, nil
		}

		return &mcp.CallToolResult{
			Content: []mcp.Content{
				&mcp.TextContent{Text: string(b)},
			},
		}, nil, nil
	})
}
