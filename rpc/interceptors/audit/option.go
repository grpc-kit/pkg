package audit

import (
	"context"
	"fmt"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/client"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/google/uuid"
	"github.com/grpc-kit/pkg/rpc"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"k8s.io/utils/pointer"
)

var (
	defaultOption = &interceptorOption{
		logger:      logrus.NewEntry(logrus.StandardLogger()),
		level:       LevelRequest,
		serviceName: "unknown",
		marshal:     protojson.MarshalOptions{},
		mustSucceed: pointer.Bool(true),
	}
)

type interceptorOption struct {
	logger *logrus.Entry
	client client.Client

	level Level

	serviceName string

	marshal     protojson.MarshalOptions
	mustSucceed *bool
}

func (o *interceptorOption) getTraceID(ctx context.Context) string {
	spanCtx := trace.SpanContextFromContext(ctx)
	if spanCtx.HasTraceID() {
		return spanCtx.TraceID().String()
	}

	return uuid.New().String()
}

func (o *interceptorOption) marshalJson(data any) (string, bool, error) {
	if protoResp, ok := data.(proto.Message); ok {
		jsonResp, err := o.marshal.Marshal(protoResp)
		if err != nil {
			return "", false, err
		}
		return string(jsonResp), true, nil
	}

	return "", false, fmt.Errorf("expected proto.Message, got %T", data)
}

func (o *interceptorOption) sendAuditEvent(ctx context.Context, ce event.Event, data *EventData) error {
	data.StageTimestamp = time.Now()

	if o.mustSucceed == nil || *o.mustSucceed {
		if err := ce.SetData(event.ApplicationJSON, data); err != nil {
			return err
		}
		if cloudevents.IsACK(o.client.Send(ctx, ce)) {
			return nil
		}
	} else {
		go func() {
			if err := ce.SetData(event.ApplicationJSON, data); err == nil {
				if cloudevents.IsUndelivered(o.client.Send(ctx, ce)) {
					o.logger.Warnf("unable to send audit event, this request %v will be not audited", data.GRPCMethod)
				}
			} else {
				o.logger.Warnf("failed to set event data: %v", err)
			}
		}()

		return nil
	}

	return fmt.Errorf("unable to send audit event, this request will be aborted")
}

func (o *interceptorOption) createEventData(ctx context.Context) *EventData {
	username, ok := rpc.GetUsernameFromContext(ctx)
	if !ok {
		username = "-"
	}
	groups, ok := rpc.GetGroupsFromContext(ctx)
	if !ok {
		groups = []string{}
	}

	eventData := &EventData{
		ServiceName: o.serviceName,
		Level:       o.level,
		AuditID:     o.getTraceID(ctx),
		Stage:       StageRequestReceived,

		// GRPCMethod:  grpcMethod,
		// GRPCService: grpcService,

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

	return eventData
}

// Option is a functional option for audit.
type Option func(o *interceptorOption)

// WithLogger 调试日志组件
func WithLogger(logger *logrus.Entry) Option {
	return func(o *interceptorOption) {
		o.logger = logger
	}
}

// WithCloudEvent 云事件客户端
func WithCloudEvent(client client.Client) Option {
	return func(o *interceptorOption) {
		o.client = client
	}
}

// WithServiceName 审计事件的服务名称
func WithServiceName(serviceName string) Option {
	return func(o *interceptorOption) {
		o.serviceName = serviceName
	}
}

// WithMustSucceed 发送的审计事件必须成功，否则本次请求失败
func WithMustSucceed(success bool) Option {
	return func(o *interceptorOption) {
		o.mustSucceed = pointer.Bool(success)
	}
}

// WithMarshal 序列化组件
func WithMarshal(marshal protojson.MarshalOptions) Option {
	return func(o *interceptorOption) {
		o.marshal = marshal
	}
}

// WithLevel 审计事件等级
func WithLevel(level Level) Option {
	return func(o *interceptorOption) {
		o.level = level
	}
}
