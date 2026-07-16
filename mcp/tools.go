package mcp

import (
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"
)

// mustJSON 将 v 序列化为 JSON 字符串，序列化失败时返回错误信息字符串。
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":"json marshal failed"}`
	}
	return string(b)
}

// GRPCConnFunc 返回本地 gRPC 连接，供 health_check 等 Tool 使用。
// 连接应由调用方惰性创建并缓存。
type GRPCConnFunc func() (*grpc.ClientConn, error)

// ServiceInfoFunc 返回服务元信息（名称、版本、git commit 等）。
type ServiceInfoFunc func() (map[string]any, error)

// GrpcMethodsFunc 返回已注册的 gRPC 方法列表。
// 每个元素包含 service、method、description 等字段。
type GrpcMethodsFunc func() ([]map[string]any, error)

// ConfigSnapshotFunc 返回脱敏后的运行配置。
type ConfigSnapshotFunc func() (map[string]any, error)

// BuiltinToolsConfig 汇总所有内置 Tool 的回调配置。
// 任意回调为 nil 时，对应 Tool 不会被注册（不报错）。
type BuiltinToolsConfig struct {
	GRPCConn    GRPCConnFunc
	ServiceInfo ServiceInfoFunc
	GrpcMethods GrpcMethodsFunc
	Config      ConfigSnapshotFunc
}

// RegisterBuiltinTools 向 MCP Server 注册全部内置 Tools。
// 各回调为 nil 时跳过对应 Tool 注册。
func RegisterBuiltinTools(server *mcp.Server, cfg BuiltinToolsConfig) {
	if server == nil {
		return
	}
	registerHealthCheckTool(server, cfg.GRPCConn)
	registerServiceInfoTool(server, cfg.ServiceInfo)
	registerGrpcMethodsTool(server, cfg.GrpcMethods)
	registerConfigTool(server, cfg.Config)
}
