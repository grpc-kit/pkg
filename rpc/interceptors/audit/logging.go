package audit

import (
	"context"
	"log/slog"
)

const (
	auditEventDeliveryFailed   = "audit_event_delivery_failed"
	auditEventEncodingFailed   = "audit_event_encoding_failed"
	auditGRPCMethodParseFailed = "audit_grpc_method_parse_failed"
)

func logAuditEventDeliveryFailed(ctx context.Context, logger *slog.Logger, grpcMethod string, err error) {
	logAuditIssue(ctx, logger, slog.LevelWarn, "failed to send audit event", auditEventDeliveryFailed, grpcMethod, err)
}

func logAuditEventDeliveryError(ctx context.Context, logger *slog.Logger, grpcMethod string, err error) {
	logAuditIssue(ctx, logger, slog.LevelError, "failed to send audit event", auditEventDeliveryFailed, grpcMethod, err)
}

func logAuditEventEncodingFailed(ctx context.Context, logger *slog.Logger, grpcMethod string, err error) {
	logAuditIssue(ctx, logger, slog.LevelWarn, "failed to encode audit event", auditEventEncodingFailed, grpcMethod, err)
}

func logAuditEventEncodingError(ctx context.Context, logger *slog.Logger, grpcMethod string, err error) {
	logAuditIssue(ctx, logger, slog.LevelError, "failed to encode audit event", auditEventEncodingFailed, grpcMethod, err)
}

func logAuditGRPCMethodParseFailed(ctx context.Context, logger *slog.Logger, fullMethod string, err error) {
	logAuditIssue(ctx, logger, slog.LevelWarn, "failed to parse gRPC method", auditGRPCMethodParseFailed, fullMethod, err)
}

func logAuditIssue(
	ctx context.Context,
	logger *slog.Logger,
	level slog.Level,
	message string,
	eventName string,
	grpcMethod string,
	err error,
) {
	logger.LogAttrs(ctx, level, message,
		slog.String("event", eventName),
		slog.String("grpc.method", grpcMethod),
		slog.Any("error", err),
	)
}
