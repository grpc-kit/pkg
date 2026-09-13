package rpc

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	pklogging "github.com/grpc-kit/pkg/logging"
)

func TestNewConfig(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	config := NewConfig(logger)
	if config.logger != logger {
		t.Fatal("NewConfig did not retain the supplied logger")
	}
	if config.KeepaliveTimeout == 0 || config.Scheme != "grpc-kit" {
		t.Fatalf("defaults = (%v, %q), want non-zero timeout and grpc-kit scheme", config.KeepaliveTimeout, config.Scheme)
	}

	config.logger.Info("native rpc logger")
	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("native log line count = %d, want 1; output = %q", got, output.String())
	}
}

func TestNewConfigNilUsesFallback(t *testing.T) {
	config := NewConfig(nil)
	if config.logger != pklogging.Fallback() {
		t.Fatal("nil slog logger did not use logging.Fallback")
	}
}
