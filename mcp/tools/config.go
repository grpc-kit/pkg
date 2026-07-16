package tools

import (
	"context"
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// registerConfigTool 注册 get_config Tool。
// 若 cfgFn 为 nil，跳过注册。
func registerConfigTool(server *mcp.Server, cfgFn ConfigSnapshotFunc) {
	if cfgFn == nil {
		return
	}

	tool := &mcp.Tool{
		Name:        "get_config",
		Description: "Get sanitized runtime configuration (sensitive fields are masked)",
	}

	mcp.AddTool(server, tool, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		cfg, err := cfgFn()
		if err != nil {
			return &mcp.CallToolResult{
				IsError: true,
				Content: []mcp.Content{
					&mcp.TextContent{Text: mustJSON(map[string]string{"error": err.Error()})},
				},
			}, nil, nil
		}

		b, err := json.Marshal(cfg)
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
