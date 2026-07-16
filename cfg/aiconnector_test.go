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
}

func testInitAIConnectorPreserved(t *testing.T) {
	c := &LocalConfig{
		AIConnector: &AIConnectorConfig{
			Enable: true,
			MCPServer: MCPServerConfig{
				Enable:    true,
				Path:      "/custom-mcp",
				Transport: "sse",
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
}
