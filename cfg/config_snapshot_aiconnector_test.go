package cfg

import "testing"

func TestToAdminAIConnectorConfig(t *testing.T) {
	config := (&LocalConfig{
		AIConnector: &AIConnectorConfig{
			Enable: true,
			MCPServer: MCPServerConfig{
				Enable:      true,
				Path:        "/custom-mcp",
				Transport:   "sse",
				AllowedTags: []string{"mcp", "chat"},
			},
		},
	}).toAdminAIConnectorConfig()

	if config.GetName() != "aiconnector" || !config.GetEnabled() {
		t.Fatalf("AI connector snapshot mismatch: %+v", config)
	}
	if !config.GetMcpServer().GetEnabled() || config.GetMcpServer().GetPath() != "/custom-mcp" {
		t.Fatalf("MCP server snapshot mismatch: %+v", config.GetMcpServer())
	}
	if config.GetMcpServer().GetTransport() != "sse" || len(config.GetMcpServer().GetAllowedTags()) != 2 {
		t.Fatalf("MCP server transport or allowed tags mismatch: %+v", config.GetMcpServer())
	}
}
