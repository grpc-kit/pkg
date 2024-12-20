package audit

import (
	"context"

	"github.com/cloudevents/sdk-go/v2/client"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/encoding/protojson"
)

type interceptorOption struct {
	logger *logrus.Entry
	client client.Client

	level Level

	serviceName string
	serviceCode string

	marshal protojson.MarshalOptions
}

func (o *interceptorOption) getTraceID(ctx context.Context) string {
	requestID := "0123456789abcdef0123456789abcdef"

	spanCtx := trace.SpanContextFromContext(ctx)
	if spanCtx.HasTraceID() {
		requestID = spanCtx.TraceID().String()
	}

	return requestID
}

// Option is a functional option for audit.
type Option func(o *interceptorOption)

func WithLogger(logger *logrus.Entry) Option {
	return func(o *interceptorOption) {
		o.logger = logger
	}
}

func WithCloudEvent(client client.Client) Option {
	return func(o *interceptorOption) {
		o.client = client
	}
}

func WithServiceName(serviceName string) Option {
	return func(o *interceptorOption) {
		o.serviceName = serviceName
	}
}

func WithServiceCode(serviceCode string) Option {
	return func(o *interceptorOption) {
		o.serviceCode = serviceCode
	}
}

func WithMarshal(marshal protojson.MarshalOptions) Option {
	return func(o *interceptorOption) {
		o.marshal = marshal
	}
}

func WithLevel(level Level) Option {
	return func(o *interceptorOption) {
		o.level = level
	}
}
