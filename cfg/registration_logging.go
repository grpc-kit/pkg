package cfg

import (
	"context"
	"errors"
	"log/slog"
	"syscall"

	pklogging "github.com/grpc-kit/pkg/logging"
)

const (
	eventAdminDatabaseUnavailable            = "cfg_admin_database_unavailable"
	eventRegistryHealthCheckFailed           = "cfg_registry_health_check_failed"
	eventRegistryHealthCheckSucceeded        = "cfg_registry_health_check_succeeded"
	eventRegistryHealthCheckRetriesExhausted = "cfg_registry_health_check_retries_exhausted"
	eventServiceRegistrationFailed           = "cfg_service_registration_failed"
)

func logAdminDatabaseUnavailable(ctx context.Context, logger *slog.Logger) {
	pklogging.OrFallback(logger).LogAttrs(ctx, slog.LevelInfo, "admin service database unavailable",
		slog.String("event", eventAdminDatabaseUnavailable),
	)
}

func logRegistryHealthCheckFailed(ctx context.Context, logger *slog.Logger, err error, retryCount, retryMax int) {
	pklogging.OrFallback(logger).LogAttrs(ctx, slog.LevelError, "service registry health check failed",
		slog.String("event", eventRegistryHealthCheckFailed),
		slog.String("error_kind", classifyRegistrationError(err)),
		slog.Int("retry_count", retryCount),
		slog.Int("retry_max", retryMax),
	)
}

func logRegistryHealthCheckSucceeded(ctx context.Context, logger *slog.Logger, retryCount, retryMax int) {
	pklogging.OrFallback(logger).LogAttrs(ctx, slog.LevelInfo, "service registry health check succeeded",
		slog.String("event", eventRegistryHealthCheckSucceeded),
		slog.Int("retry_count", retryCount),
		slog.Int("retry_max", retryMax),
	)
}

func logRegistryHealthCheckRetriesExhausted(ctx context.Context, logger *slog.Logger, retryCount, retryMax int) {
	pklogging.OrFallback(logger).LogAttrs(ctx, slog.LevelError, "service registry health check retries exhausted",
		slog.String("event", eventRegistryHealthCheckRetriesExhausted),
		slog.Int("retry_count", retryCount),
		slog.Int("retry_max", retryMax),
	)
}

func logServiceRegistrationFailed(ctx context.Context, logger *slog.Logger, err error) {
	pklogging.OrFallback(logger).LogAttrs(ctx, slog.LevelError, "service registration failed",
		slog.String("event", eventServiceRegistrationFailed),
		slog.String("error_kind", classifyRegistrationError(err)),
	)
}

func classifyRegistrationError(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	}

	var timeoutError interface{ Timeout() bool }
	if errors.As(err, &timeoutError) && timeoutError.Timeout() {
		return "timeout"
	}

	return "other"
}
