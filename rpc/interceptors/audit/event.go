package audit

import "time"

// Level 定义审计级别
type Level string

// Valid audit levels
const (
	// LevelNone disables auditing
	LevelNone Level = "none"
	// LevelMetadata provides the basic level of auditing.
	LevelMetadata Level = "metadata"
	// LevelRequest provides Metadata level of auditing, and additionally
	// logs the request object (does not apply for non-resource requests).
	LevelRequest Level = "request"
	// LevelRequestResponse provides Request level of auditing, and additionally
	// logs the response object (does not apply for non-resource requests).
	LevelRequestResponse Level = "request_response"
)

// EventData 审计事件
type EventData struct {
	// 唯一标识服务名称，如：netdev.v1.oneops.api.grpc-kit.com
	ServiceName string `json:"service_name"`
	// 唯一标识服务代号，如：netdev.v1.oneops
	ServiceCode string `json:"service_code"`

	Level Level `json:"level"`

	// 当前请求用户
	User struct {
		UID      string              `json:"uid"`
		Username string              `json:"username"`
		Groups   []string            `json:"groups"`
		Extra    map[string][]string `json:"extra"`
	} `json:"user"`

	// 用户来源 ip 列表
	SourceIPs []string `json:"source_ips"`

	// UserAgent 用户代理
	UserAgent string `json:"user_agent"`

	RequestReceivedTimestamp time.Time `json:"request_received_timestamp"`
	StageTimestamp           time.Time `json:"stage_timestamp"`

	GRPCMethod  string `json:"grpc_method"`
	GRPCService string `json:"grpc_service"`

	RequestID string `json:"request_id"`

	RequestObject  string `json:"request_object"`
	ResponseObject string `json:"response_object"`
}
