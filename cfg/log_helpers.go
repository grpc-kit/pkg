package cfg

import (
	"context"
	"fmt"
	"log/slog"

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
