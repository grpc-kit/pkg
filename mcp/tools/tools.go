package tools

import (
	"encoding/json"

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

// GRPCConnFunc 返回本地 gRPC 连接，供 AutoBridge 等需要直连 gRPC 的场景使用。
// 连接应由调用方惰性创建并缓存。
type GRPCConnFunc func() (*grpc.ClientConn, error)
