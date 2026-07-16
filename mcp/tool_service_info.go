package mcp

import (
	"context"
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerServiceInfoTool 注册 get_service_info Tool。
// 若 infoFn 为 nil，跳过注册。
func registerServiceInfoTool(server *mcp.Server, infoFn ServiceInfoFunc) {
	if infoFn == nil {
		return
	}

	tool := &mcp.Tool{
		Name:        "get_service_info",
		Description: "Get service metadata: name, version, git commit, build date, go version, etc.",
	}

	mcp.AddTool(server, tool, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		info, err := infoFn()
		if err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: mustJSON(map[string]string{"error": err.Error()})},
				},
			}, nil, nil
		}

		b, err := json.Marshal(info)
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
