package auth

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	pklogging "github.com/grpc-kit/pkg/logging"
)

func TestNewClientUsesFallbackLogger(t *testing.T) {
	client, err := NewClient(t.Context(), &Config{})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client.logger != pklogging.Fallback() {
		t.Fatal("NewClient did not use logging.Fallback")
	}
}

func TestWithLoggerOption(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	client := new(Client)

	got := client.WithLoggerOption(logger)

	if got != client {
		t.Fatal("WithLoggerOption did not return its receiver")
	}
	if client.logger != logger {
		t.Fatal("WithLoggerOption did not retain the supplied logger")
	}
	client.logger.Warn("native auth logger")
	if count := strings.Count(output.String(), "\n"); count != 1 {
		t.Fatalf("native log line count = %d, want 1; output = %q", count, output.String())
	}
}

func TestWithLoggerOptionNilUsesFallback(t *testing.T) {
	client := new(Client).WithLoggerOption(nil)

	if client.logger != pklogging.Fallback() {
		t.Fatal("nil slog logger did not use logging.Fallback")
	}
}
