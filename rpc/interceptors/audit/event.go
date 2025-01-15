package audit

import (
	"time"

	"github.com/grpc-kit/pkg/errs"
)

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

type Stage string

// Valid audit stages.
const (
	// StageRequestReceived The stage for events generated as soon as the audit handler receives the request, and before it
	// is delegated down the handler chain.
	StageRequestReceived Stage = "request_received"
	// StageResponseComplete The stage for events generated once the response body has been completed, and no more bytes
	// will be sent.
	StageResponseComplete Stage = "response_complete"
)

// Status 响应状态
type Status struct {
	Status string `json:"status"` // 范围：success, failure
	Reason string `json:"reason"` // 对应：errs.Status.Status
	Code   int    `json:"code"`   // 对应：errs.Status.HTTPCode
}

// EventData 审计事件
type EventData struct {
	// 唯一标识服务名称，如：netdev.v1.oneops.api.grpc-kit.com
	ServiceName string `json:"service_name"`

	// 审计级别，如：none / metadata / request / request_response
	Level Level `json:"level"`

	// 审计 ID，每个请求唯一，一般同为 request_id
	AuditID string `json:"audit_id"`

	// TODO;
	Stage Stage `json:"stage"`

	GRPCMethod  string `json:"grpc_method"`
	GRPCService string `json:"grpc_service"`

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

	// TODO; 执行完成后状态记录
	ResponseStatus Status `json:"response_status"`

	RequestObject  string `json:"request_object"`
	ResponseObject string `json:"response_object"`

	RequestReceivedTimestamp time.Time `json:"request_received_timestamp"`
	StageTimestamp           time.Time `json:"stage_timestamp"`
}

func (e *EventData) setResponseObject(data string) {
	e.ResponseObject = data
	e.Stage = StageResponseComplete
	e.StageTimestamp = time.Now()
}

func (e *EventData) setRequestObject(data string) {
	e.RequestObject = data
	e.Stage = StageRequestReceived
	e.StageTimestamp = time.Now()
}

func (e *EventData) setResponseStatus(err error) {
	if err == nil {
		e.ResponseStatus.Status = "success"
		e.ResponseStatus.Reason = "OK"
		e.ResponseStatus.Code = 200
		return
	}

	st := errs.FromError(err)
	e.ResponseStatus.Status = "failure"
	e.ResponseStatus.Reason = st.GetStatus()
	e.ResponseStatus.Code = st.HTTPStatusCode()
}
