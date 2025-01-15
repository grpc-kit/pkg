package rpc

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
)

var meter = otel.Meter("github.com/grpc-kit/pkg")

var (
	auditEventSendErrors metric.Float64Counter
)

func init() {
	var err error

	auditEventSendErrors, err = meter.Float64Counter(
		"grpc_kit.audit_event.send_errors",
		metric.WithDescription("Counts the number of failed attempts to send audit events."),
	)
	if err != nil {
		panic(err)
	}
}

// MetricAuditEventSendErrorsIncr 推送审计事件失败次数+1
func MetricAuditEventSendErrorsIncr(ctx context.Context) {
	auditEventSendErrors.Add(ctx, 1)
}
