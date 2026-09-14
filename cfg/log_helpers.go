package cfg

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"syscall"

	pklogging "github.com/grpc-kit/pkg/logging"
)

func logDebugf(ctx context.Context, logger *slog.Logger, format string, args ...any) {
	pklogging.OrFallback(logger).DebugContext(ctx, fmt.Sprintf(format, args...))
}

func logInfof(ctx context.Context, logger *slog.Logger, format string, args ...any) {
	pklogging.OrFallback(logger).InfoContext(ctx, fmt.Sprintf(format, args...))
}

func logWarnf(ctx context.Context, logger *slog.Logger, format string, args ...any) {
	pklogging.OrFallback(logger).WarnContext(ctx, fmt.Sprintf(format, args...))
}

func logErrorf(ctx context.Context, logger *slog.Logger, format string, args ...any) {
	pklogging.OrFallback(logger).ErrorContext(ctx, fmt.Sprintf(format, args...))
}

func classifySafeError(err error) string {
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
