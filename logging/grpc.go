package logging

import (
	"context"
	"log/slog"

	grpclogging "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
)

// NewGRPCLogger adapts slog to go-grpc-middleware's logging.Logger interface.
func NewGRPCLogger(logger *slog.Logger) grpclogging.Logger {
	logger = OrFallback(logger)

	return grpclogging.LoggerFunc(func(ctx context.Context, level grpclogging.Level, msg string, fields ...any) {
		attrs := make([]slog.Attr, 0, (len(fields)+1)/2)
		for i := 0; i < len(fields); i += 2 {
			key := fields[i].(string)
			value := any("")
			if i+1 < len(fields) {
				value = fields[i+1]
			}
			attrs = append(attrs, slog.Any(key, value))
		}
		logger.LogAttrs(ctx, slog.Level(level), msg, attrs...)
	})
}
