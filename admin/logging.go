package admin

import (
	"context"
	"fmt"
	"log/slog"
)

func logInfof(ctx context.Context, logger *slog.Logger, format string, args ...any) {
	logger.InfoContext(ctx, fmt.Sprintf(format, args...))
}

func logWarnf(ctx context.Context, logger *slog.Logger, format string, args ...any) {
	logger.WarnContext(ctx, fmt.Sprintf(format, args...))
}

func logErrorf(ctx context.Context, logger *slog.Logger, format string, args ...any) {
	logger.ErrorContext(ctx, fmt.Sprintf(format, args...))
}
