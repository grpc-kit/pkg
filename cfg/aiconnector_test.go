package cfg

import (
	"testing"
)

func TestInitAIConnector(t *testing.T) {
	t.Run("Nil", testInitAIConnectorNil)
	t.Run("Defaults", testInitAIConnectorDefaults)
	t.Run("Preserved", testInitAIConnectorPreserved)
	t.Run("Disabled", testInitAIConnectorDisabled)
}

func testInitAIConnectorNil(t *testing.T) {
	c := &LocalConfig{}
	if err := c.initAIConnector(); err != nil {
		t.Fatalf("initAIConnector() error: %v", err)
	}
	if c.AIConnector == nil {
		t.Fatal("AIConnector is nil after init")
	}
	if c.AIConnector.Enable {
		t.Error("Enable should be false by default")
	}
	if c.AIConnector.MCPServer.Enable {
		t.Error("MCPServer.Enable should be false by default")
	}
	if c.AIConnector.MCPServer.Path != "/mcp" {
		t.Errorf("MCPServer.Path = %q, want %q", c.AIConnector.MCPServer.Path, "/mcp")
	}
	if c.AIConnector.MCPServer.Transport != "streamable_http" {
		t.Errorf("MCPServer.Transport = %q, want %q", c.AIConnector.MCPServer.Transport, "streamable_http")
	}
	if got := c.AIConnector.MCPServer.AllowedTags; len(got) != 1 || got[0] != "mcp" {
		t.Errorf("MCPServer.AllowedTags = %v, want [\"mcp\"] (default filled)", got)
	}
}

func testInitAIConnectorDefaults(t *testing.T) {
	c := &LocalConfig{
		AIConnector: &AIConnectorConfig{
			Enable: true,
			MCPServer: MCPServerConfig{
				Enable: true,
			},
		},
	}
	if err := c.initAIConnector(); err != nil {
		t.Fatalf("initAIConnector() error: %v", err)
	}
	if !c.AIConnector.Enable {
		t.Error("Enable should remain true")
	}
	if !c.AIConnector.MCPServer.Enable {
		t.Error("MCPServer.Enable should remain true")
	}
	if c.AIConnector.MCPServer.Path != "/mcp" {
		t.Errorf("MCPServer.Path = %q, want %q (default filled)", c.AIConnector.MCPServer.Path, "/mcp")
	}
	if c.AIConnector.MCPServer.Transport != "streamable_http" {
		t.Errorf("MCPServer.Transport = %q, want %q (default filled)", c.AIConnector.MCPServer.Transport, "streamable_http")
	}
	if got := c.AIConnector.MCPServer.AllowedTags; len(got) != 1 || got[0] != "mcp" {
		t.Errorf("MCPServer.AllowedTags = %v, want [\"mcp\"] (default filled)", got)
	}
}

func testInitAIConnectorPreserved(t *testing.T) {
	c := &LocalConfig{
		AIConnector: &AIConnectorConfig{
			Enable: true,
			MCPServer: MCPServerConfig{
				Enable:      true,
				Path:        "/custom-mcp",
				Transport:   "sse",
				AllowedTags: []string{"chat", "note"},
			},
		},
	}
	if err := c.initAIConnector(); err != nil {
		t.Fatalf("initAIConnector() error: %v", err)
	}
	if c.AIConnector.MCPServer.Path != "/custom-mcp" {
		t.Errorf("MCPServer.Path = %q, want %q (preserved)", c.AIConnector.MCPServer.Path, "/custom-mcp")
	}
	if c.AIConnector.MCPServer.Transport != "sse" {
		t.Errorf("MCPServer.Transport = %q, want %q (preserved)", c.AIConnector.MCPServer.Transport, "sse")
	}
	if got := c.AIConnector.MCPServer.AllowedTags; len(got) != 2 || got[0] != "chat" || got[1] != "note" {
		t.Errorf("MCPServer.AllowedTags = %v, want [\"chat\" \"note\"] (preserved)", got)
	}
}

func testInitAIConnectorDisabled(t *testing.T) {
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
	// Even when disabled, defaults should be filled (not short-circuited)
	if c.AIConnector.MCPServer.Path != "/mcp" {
		t.Errorf("MCPServer.Path = %q, want %q (should fill default even when disabled)", c.AIConnector.MCPServer.Path, "/mcp")
	}
	if c.AIConnector.MCPServer.Transport != "streamable_http" {
		t.Errorf("MCPServer.Transport = %q, want %q (should fill default even when disabled)", c.AIConnector.MCPServer.Transport, "streamable_http")
	}
	if got := c.AIConnector.MCPServer.AllowedTags; len(got) != 1 || got[0] != "mcp" {
		t.Errorf("MCPServer.AllowedTags = %v, want [\"mcp\"] (should fill default even when disabled)", got)
	}
}

func TestDefaultAIConnectorConfig(t *testing.T) {
	d := DefaultAIConnectorConfig()
	if d == nil {
		t.Fatal("DefaultAIConnectorConfig() returned nil")
	}
	if d.Enable {
		t.Error("Enable should be false")
	}
	if d.MCPServer.Enable {
		t.Error("MCPServer.Enable should be false")
	}
	if d.MCPServer.Path != "/mcp" {
		t.Errorf("MCPServer.Path = %q, want %q", d.MCPServer.Path, "/mcp")
	}
	if d.MCPServer.Transport != "streamable_http" {
		t.Errorf("MCPServer.Transport = %q, want %q", d.MCPServer.Transport, "streamable_http")
	}
	if got := d.MCPServer.AllowedTags; len(got) != 1 || got[0] != "mcp" {
		t.Errorf("MCPServer.AllowedTags = %v, want [\"mcp\"]", got)
	}
}
