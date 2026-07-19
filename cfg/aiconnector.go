package cfg

// AIConnectorConfig AI 连接器配置
// 一期仅包含 MCP Server 配置；LLM Client 配置将在第二阶段添加
type AIConnectorConfig struct {
	// 是否启用 AI 连接器（默认 false）
	Enable bool `mapstructure:"enable"`

	// MCP Server 配置
	MCPServer MCPServerConfig `mapstructure:"mcp_server"`
}

// MCPServerConfig MCP 服务端配置
type MCPServerConfig struct {
	// 是否启用 MCP 服务端（默认 false）
	Enable bool `mapstructure:"enable"`

	// MCP 服务端点路径（默认 "/mcp"）
	Path string `mapstructure:"path"`

	// 传输协议：streamable_http | sse（默认 streamable_http）
	Transport string `mapstructure:"transport"`

	// AllowedTags 控制 AutoBridge 仅暴露 tags 命中此白名单的 gRPC 方法为 MCP tool。
	// 匹配语义：operation 的 tags 列表中只要有一个值出现在 AllowedTags 中即命中（OR 语义）。
	// 空列表 = 不过滤，暴露全部有 HTTP 映射的 gRPC 方法（向后兼容）。
	// 非空列表 = 仅暴露命中的方法，未设 tags 或未命中的方法不暴露。
	// 示例：allowed_tags: ["mcp"] 仅暴露 openapiv2.yaml 中标注了 tags: [..., "mcp"] 的方法。
	AllowedTags []string `mapstructure:"allowed_tags"`
}

// DefaultAIConnectorConfig 返回 AIConnectorConfig 默认值
func DefaultAIConnectorConfig() *AIConnectorConfig {
	return &AIConnectorConfig{
		Enable: false,
		MCPServer: MCPServerConfig{
			Enable:    false,
			Path:      "/mcp",
			Transport: "streamable_http",
		},
	}
}

// initAIConnector 初始化 AI 连接器配置
// 放在 Init 链最后，因为 AI 连接器可能需要引用其他子系统配置
func (c *LocalConfig) initAIConnector() error {
	if c.AIConnector == nil {
		c.AIConnector = DefaultAIConnectorConfig()
		return nil
	}

	// 填充 MCP Server 默认值（即使 Enable=false 也填充，后续 handler 挂载需要读取）
	mcp := &c.AIConnector.MCPServer
	if mcp.Path == "" {
		mcp.Path = "/mcp"
	}
	if mcp.Transport == "" {
		mcp.Transport = "streamable_http"
	}

	// 注意：MCP Server 的名称和版本使用 pkg/vars/base.go 中的
	// vars.Appname 和 vars.ReleaseVersion，无需在此处初始化
	// 注意：MCP 认证复用 SecurityConfig.Authentication / Authorization，
	// 不在 AIConnectorConfig 中配置，无需在此处初始化

	// LLM Client 初始化推迟到第二阶段

	return nil
}
