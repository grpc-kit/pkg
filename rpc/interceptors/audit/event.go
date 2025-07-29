package audit

import (
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"golang.org/x/net/context"
	"google.golang.org/protobuf/proto"

	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/rpc"
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
	opt *interceptorOption

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

func newEventDataFromContext(ctx context.Context, opt *interceptorOption, grpcService, grpcMethod string) *EventData {
	username, ok := rpc.GetUsernameFromContext(ctx)
	if !ok {
		username = "-"
	}
	groups, ok := rpc.GetGroupsFromContext(ctx)
	if !ok {
		groups = []string{}
	}

	e := &EventData{
		opt: opt,

		ServiceName: opt.serviceName,
		Level:       opt.level,
		AuditID:     opt.getTraceID(ctx),
		Stage:       StageRequestReceived,
		GRPCMethod:  grpcMethod,
		GRPCService: grpcService,
		User: struct {
			UID      string              `json:"uid"`
			Username string              `json:"username"`
			Groups   []string            `json:"groups"`
			Extra    map[string][]string `json:"extra"`
		}{UID: username, Username: username, Groups: groups, Extra: make(map[string][]string, 0)},

		SourceIPs: rpc.GetSourceIPsFromMetadata(ctx),
		UserAgent: rpc.GetUserAgentFromMetadata(ctx),

		RequestReceivedTimestamp: time.Now(),
	}

	return e
}

func (e *EventData) setResponseObject(grpcErr error, message interface{}) {
	e.Stage = StageResponseComplete
	e.StageTimestamp = time.Now()

	if grpcErr != nil {
		st := errs.FromError(grpcErr)

		e.ResponseStatus.Status = "failure"
		e.ResponseStatus.Reason = st.GetStatus()
		e.ResponseStatus.Code = st.HTTPStatusCode()
		e.ResponseObject = grpcErr.Error()
	} else {
		e.ResponseStatus.Status = "success"
		e.ResponseStatus.Reason = "OK"
		e.ResponseStatus.Code = 200

		if protoResp, ok := message.(proto.Message); ok {
			jsonResp, err := e.opt.marshal.Marshal(protoResp)
			if err != nil {
				// TODO; 这里执行成功了，但是序列化失败返回记录了错误
				e.ResponseObject = err.Error()
			} else {
				e.ResponseObject = string(jsonResp)
			}
		}
	}
}

func (e *EventData) setRequestObject(message interface{}) {
	e.Stage = StageRequestReceived
	e.StageTimestamp = time.Now()

	if protoResp, ok := message.(proto.Message); ok {
		jsonResp, err := e.opt.marshal.Marshal(protoResp)
		if err != nil {
			e.RequestObject = err.Error()
		} else {
			e.RequestObject = string(jsonResp)
		}
	}
}

func (e *EventData) sendEvent(ctx context.Context) error {
	ce := event.New()
	ce.SetSource(e.ServiceName)
	ce.SetSubject(e.GRPCMethod)
	ce.SetType("internal.audit")
	ce.SetSpecVersion(event.CloudEventsVersionV1)

	e.StageTimestamp = time.Now()

	var err error

	if e.opt.mustSucceed == nil || *e.opt.mustSucceed {
		if err = ce.SetData(event.ApplicationJSON, e); err == nil {
			if cloudevents.IsACK(e.opt.client.Send(ctx, ce)) {
				return nil
			} else {
				err = fmt.Errorf("send audit event not ack")
			}
		}
	} else {
		go func() {
			if err = ce.SetData(event.ApplicationJSON, e); err == nil {
				if cloudevents.IsUndelivered(e.opt.client.Send(ctx, ce)) {
					rpc.MetricAuditEventSendErrorsIncr(ctx)

					e.opt.logger.Warnf("unable to send audit event, this request %v will be not audited", e.GRPCMethod)
				}
			} else {
				rpc.MetricAuditEventSendErrorsIncr(ctx)

				e.opt.logger.Warnf("failed to set event data: %v", err)
			}
		}()

		// 审计日志推送失败，无需终止本次请求
		return nil
	}

	if err != nil {
		rpc.MetricAuditEventSendErrorsIncr(ctx)

		e.opt.logger.Errorf("failed to set event data: %v", err)
	}

	return fmt.Errorf("unable to send audit event, this request will be aborted")
}
