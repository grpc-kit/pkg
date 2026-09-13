package cfg

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"

	grpclogging "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	pklogging "github.com/grpc-kit/pkg/logging"
)

// initDebugger 用于初始化日志实例。
func (c *LocalConfig) initDebugger() error {
	c.logger = c.newDebuggerLogger(os.Stdout)
	return nil
}

func (c *LocalConfig) newDebuggerLogger(w io.Writer) *slog.Logger {
	if c.Debugger == nil {
		c.Debugger = &DebuggerConfig{
			LogLevel:    "info",
			LogFormat:   "text",
			EnablePprof: false,
		}
	}

	logLevel := c.Debugger.LogLevel
	if logLevel == "" {
		logLevel = "error"
	}
	level, ok := pklogging.ParseLevel(logLevel)
	if !ok {
		level = slog.LevelWarn
	}

	logFormat := c.Debugger.LogFormat
	if logFormat == "" {
		logFormat = string(pklogging.FormatText)
	}
	format, ok := pklogging.ParseFormat(logFormat)
	if !ok {
		format = pklogging.FormatText
	}

	return pklogging.New(w, format, &slog.HandlerOptions{Level: level}).With(
		slog.String("service_name", c.GetServiceName()),
	)
}

// GetLogger 用于获取当前配置的日志记录器。
func (c *LocalConfig) GetLogger() *slog.Logger {
	return c.logger
}

func (c *LocalConfig) interceptorLogger(logger *slog.Logger) grpclogging.Logger {
	logger = pklogging.OrFallback(logger)

	return grpclogging.LoggerFunc(func(ctx context.Context, level grpclogging.Level, msg string, fields ...any) {
		attrs := make([]slog.Attr, 0, (len(fields)+1)/2+1)
		iterator := grpclogging.Fields(fields).Iterator()
		for iterator.Next() {
			key, value := iterator.At()
			if key == "grpc.method" {
				method, ok := value.(string)
				if ok {
					switch strings.TrimSpace(method) {
					case "Check", "Watch", "HealthCheck":
						return
					}
				}
			}
			attrs = append(attrs, slog.Any(key, value))
		}

		slogLevel := slog.LevelError
		switch level {
		case grpclogging.LevelDebug:
			slogLevel = slog.LevelDebug
		case grpclogging.LevelInfo:
			slogLevel = slog.LevelInfo
		case grpclogging.LevelWarn:
			slogLevel = slog.LevelWarn
		case grpclogging.LevelError:
			slogLevel = slog.LevelError
		default:
			attrs = append(attrs, slog.Any("grpc.logger_level", level))
		}

		logger.LogAttrs(ctx, slogLevel, msg, attrs...)
	})
}
