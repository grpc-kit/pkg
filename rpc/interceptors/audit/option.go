package audit

import (
	"context"
	"fmt"
	"strings"

	"github.com/cloudevents/sdk-go/v2/client"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
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

	serviceName string // netdev.v1.oneops.api.grpc-kit.com
	grpcService string // default.api.oneops.netdev.v1.OneopsNetdev
	grpcMethod  string // DisplaySwitchPortVlans

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

/*
func (o *interceptorOption) sendAuditEvent(ctx context.Context, data *EventData) error {
	ce := event.New()
	ce.SetSource(o.serviceName)
	ce.SetSubject(o.grpcMethod)
	ce.SetType("internal.audit")
	ce.SetSpecVersion(event.CloudEventsVersionV1)

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
*/

func (o *interceptorOption) setGRPCMethod(fullMethod string) error {
	parts := strings.Split(fullMethod, "/")
	if len(parts) < 3 {
		return fmt.Errorf("failed to parse grpc metho: %s, ignore audit", fullMethod)
	}

	o.grpcService = parts[1]
	o.grpcMethod = parts[2]

	return nil
}

func (o *interceptorOption) auditRequired() bool {
	// 审计等级为 LevelNone 时，不需要审计
	if o.level == LevelNone {
		return false
	}

	// TODO；针对特殊的 method 不做审计
	switch o.grpcMethod {
	case "HealthCheck":
		return false
	}

	return true
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
