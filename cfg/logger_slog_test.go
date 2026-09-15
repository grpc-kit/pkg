package cfg

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	grpclogging "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	pklogging "github.com/grpc-kit/pkg/logging"
)

func TestNewDebuggerLoggerLevel(t *testing.T) {
	tests := []struct {
		name     string
		debugger *DebuggerConfig
		want     slog.Level
	}{
		{name: "nil debugger", want: slog.LevelInfo},
		{name: "empty level", debugger: &DebuggerConfig{}, want: slog.LevelError},
		{name: "panic", debugger: &DebuggerConfig{LogLevel: "panic"}, want: pklogging.LevelPanic},
		{name: "fatal", debugger: &DebuggerConfig{LogLevel: "fatal"}, want: pklogging.LevelFatal},
		{name: "error", debugger: &DebuggerConfig{LogLevel: "error"}, want: slog.LevelError},
		{name: "warn", debugger: &DebuggerConfig{LogLevel: "warn"}, want: slog.LevelWarn},
		{name: "info", debugger: &DebuggerConfig{LogLevel: "info"}, want: slog.LevelInfo},
		{name: "debug", debugger: &DebuggerConfig{LogLevel: "debug"}, want: slog.LevelDebug},
		{name: "documented trace falls back", debugger: &DebuggerConfig{LogLevel: "trace"}, want: slog.LevelWarn},
		{name: "unknown falls back", debugger: &DebuggerConfig{LogLevel: "invalid"}, want: slog.LevelWarn},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := loggerTestConfig(tt.debugger)
			logger := config.newDebuggerLogger(io.Discard)
			if !logger.Enabled(t.Context(), tt.want) {
				t.Errorf("configured level %v is disabled", tt.want)
			}
			if logger.Enabled(t.Context(), tt.want-1) {
				t.Errorf("level %v below configured level %v is enabled", tt.want-1, tt.want)
			}
		})
	}
}

func TestNewDebuggerLoggerFormatAndFields(t *testing.T) {
	tests := []struct {
		name     string
		format   string
		wantJSON bool
	}{
		{name: "empty uses text"},
		{name: "text", format: "text"},
		{name: "json", format: "json", wantJSON: true},
		{name: "unknown uses text", format: "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			config := loggerTestConfig(&DebuggerConfig{LogLevel: "debug", LogFormat: tt.format})
			logger := config.newDebuggerLogger(&output)
			logger.Info("message", slog.String("request_id", "request-test"))

			if tt.wantJSON {
				var record map[string]any
				if err := json.Unmarshal(output.Bytes(), &record); err != nil {
					t.Fatalf("decode JSON output %q: %v", output.String(), err)
				}
				for key, want := range map[string]string{
					"level": "info", "msg": "message", "request_id": "request-test", "service_name": "service.api",
				} {
					if got := record[key]; got != want {
						t.Errorf("record[%q] = %v, want %q", key, got, want)
					}
				}
				if timestamp, ok := record["time"].(string); !ok {
					t.Fatalf("record[time] = %T, want string", record["time"])
				} else if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
					t.Errorf("record[time] = %q, want RFC3339Nano: %v", timestamp, err)
				}
				return
			}

			for _, want := range []string{"level=info", "msg=message", "request_id=request-test", "service_name=service.api"} {
				if !strings.Contains(output.String(), want) {
					t.Errorf("text output %q does not contain %q", output.String(), want)
				}
			}
		})
	}
}

func TestDebuggerLoggersDoNotShareGlobalLevel(t *testing.T) {
	debugLogger := loggerTestConfig(&DebuggerConfig{LogLevel: "debug"}).newDebuggerLogger(io.Discard)
	errorLogger := loggerTestConfig(&DebuggerConfig{LogLevel: "error"}).newDebuggerLogger(io.Discard)

	if !debugLogger.Enabled(t.Context(), slog.LevelDebug) {
		t.Fatal("debug logger unexpectedly disabled debug")
	}
	if errorLogger.Enabled(t.Context(), slog.LevelDebug) {
		t.Fatal("error logger unexpectedly enabled debug")
	}
}

func TestInterceptorLoggerFiltersHealthMethods(t *testing.T) {
	var output bytes.Buffer
	config := loggerTestConfig(&DebuggerConfig{LogLevel: "debug", LogFormat: "json"})
	adapter := config.interceptorLogger(config.newDebuggerLogger(&output))

	adapter.Log(t.Context(), grpclogging.LevelInfo, "health", "grpc.method", "Check")
	if output.Len() != 0 {
		t.Fatalf("filtered health log output = %q, want empty", output.String())
	}

	adapter.Log(t.Context(), grpclogging.LevelInfo, "request", "grpc.method", "Get", "request_id", "request-test")
	if !strings.Contains(output.String(), `"grpc.method":"Get"`) || !strings.Contains(output.String(), `"request_id":"request-test"`) {
		t.Fatalf("interceptor fields missing from %q", output.String())
	}
}

func TestInterceptorLoggerMapsUnknownLevelToError(t *testing.T) {
	var output bytes.Buffer
	config := loggerTestConfig(&DebuggerConfig{LogLevel: "debug", LogFormat: "json"})
	adapter := config.interceptorLogger(config.newDebuggerLogger(&output))

	adapter.Log(context.Background(), grpclogging.Level(99), "unknown")
	if !strings.Contains(output.String(), `"level":"error"`) || !strings.Contains(output.String(), `"grpc.logger_level":99`) {
		t.Fatalf("unknown-level output = %q", output.String())
	}
}

func loggerTestConfig(debugger *DebuggerConfig) *LocalConfig {
	return &LocalConfig{
		Services: &ServicesConfig{ServiceCode: "service", APIEndpoint: "api"},
		Debugger: debugger,
	}
}
