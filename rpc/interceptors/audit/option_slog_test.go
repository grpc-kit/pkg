package audit

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	pklogging "github.com/grpc-kit/pkg/logging"
)

func TestWithLogger(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	option := new(interceptorOption)

	WithLogger(logger)(option)

	if option.logger != logger {
		t.Fatal("WithLogger did not retain the supplied logger")
	}
	option.logger.Warn("native audit logger")
	if count := strings.Count(output.String(), "\n"); count != 1 {
		t.Fatalf("native log line count = %d, want 1; output = %q", count, output.String())
	}
}

func TestWithLoggerNilUsesFallback(t *testing.T) {
	option := new(interceptorOption)
	WithLogger(nil)(option)

	if option.logger != pklogging.Fallback() {
		t.Fatal("nil slog logger did not use logging.Fallback")
	}
}

func TestDefaultOptionUsesFallback(t *testing.T) {
	if defaultOption.logger != pklogging.Fallback() {
		t.Fatal("default audit option did not use logging.Fallback")
	}
}
