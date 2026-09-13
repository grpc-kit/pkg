package admin

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	pklogging "github.com/grpc-kit/pkg/logging"
)

func TestNewUsesFallbackLogger(t *testing.T) {
	api := New()

	if api.logger != pklogging.Fallback() {
		t.Fatal("New did not use logging.Fallback")
	}
	if api.config.logger != api.logger {
		t.Fatal("config and API loggers differ")
	}
}

func TestWithLogger(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	api := New(WithLogger(logger))

	if api.logger != logger {
		t.Fatal("WithLogger did not retain the supplied logger")
	}
	logWarnf(t.Context(), api.logger, "admin operation failed: %v", errors.New("boom"))
	if count := strings.Count(output.String(), "\n"); count != 1 {
		t.Fatalf("native log line count = %d, want 1; output = %q", count, output.String())
	}
	if !strings.Contains(output.String(), `"msg":"admin operation failed: boom"`) {
		t.Fatalf("formatted message was not preserved: %q", output.String())
	}
}

func TestWithLoggerNilUsesFallback(t *testing.T) {
	api := New(WithLogger(nil))

	if api.logger != pklogging.Fallback() {
		t.Fatal("nil slog logger did not use logging.Fallback")
	}
}
