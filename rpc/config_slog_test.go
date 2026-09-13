package rpc

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	pklogging "github.com/grpc-kit/pkg/logging"
	"github.com/sirupsen/logrus"
)

func TestNewConfigWithSlog(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	config := NewConfigWithSlog(logger)
	if config.logger != logger {
		t.Fatal("NewConfigWithSlog did not retain the supplied logger")
	}
	if config.KeepaliveTimeout == 0 || config.Scheme != "grpc-kit" {
		t.Fatalf("defaults = (%v, %q), want non-zero timeout and grpc-kit scheme", config.KeepaliveTimeout, config.Scheme)
	}

	config.logger.Info("native rpc logger")
	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("native log line count = %d, want 1; output = %q", got, output.String())
	}
}

func TestNewConfigWithSlogNilUsesFallback(t *testing.T) {
	config := NewConfigWithSlog(nil)
	if config.logger != pklogging.Fallback() {
		t.Fatal("nil slog logger did not use logging.Fallback")
	}
}

func TestNewConfigLegacyLoggerWritesOnce(t *testing.T) {
	var output bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&output)
	logger.SetFormatter(&logrus.JSONFormatter{})
	entry := logger.WithField("component", "rpc")

	config := NewConfig(entry)
	config.logger.Info("legacy rpc logger")

	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("legacy log line count = %d, want 1; output = %q", got, output.String())
	}
	if !strings.Contains(output.String(), `"component":"rpc"`) {
		t.Fatalf("legacy logger fields were not preserved: %q", output.String())
	}
}

func TestNewConfigLegacyNilUsesFallback(t *testing.T) {
	config := NewConfig(nil)
	if config.logger != pklogging.Fallback() {
		t.Fatal("nil legacy logger did not use logging.Fallback")
	}
}
