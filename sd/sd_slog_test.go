package sd

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	pklogging "github.com/grpc-kit/pkg/logging"
	"github.com/sirupsen/logrus"
)

func TestNewConnectorWithSlog(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	connector, err := NewConnectorWithSlog(logger, ETCDV3, "127.0.0.1:2379")
	if err != nil {
		t.Fatalf("NewConnectorWithSlog() error = %v", err)
	}
	if connector.logger != logger {
		t.Fatal("NewConnectorWithSlog did not retain the supplied logger")
	}
	if connector.Driver != ETCDV3 || connector.Hosts != "127.0.0.1:2379" {
		t.Fatalf("connector fields = (%d, %q), want (%d, %q)", connector.Driver, connector.Hosts, ETCDV3, "127.0.0.1:2379")
	}

	connector.logger.Info("native sd logger")
	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("native log line count = %d, want 1; output = %q", got, output.String())
	}
}

func TestNewConnectorWithSlogNilUsesFallback(t *testing.T) {
	connector, err := NewConnectorWithSlog(nil, ETCDV3, "127.0.0.1:2379")
	if err != nil {
		t.Fatalf("NewConnectorWithSlog() error = %v", err)
	}
	if connector.logger != pklogging.Fallback() {
		t.Fatal("nil slog logger did not use logging.Fallback")
	}
}

func TestNewConnectorLegacyLoggerWritesOnce(t *testing.T) {
	var output bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&output)
	logger.SetFormatter(&logrus.JSONFormatter{})
	entry := logger.WithField("component", "sd")

	connector, err := NewConnector(entry, ETCDV3, "127.0.0.1:2379")
	if err != nil {
		t.Fatalf("NewConnector() error = %v", err)
	}
	connector.logger.Info("legacy sd logger")

	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("legacy log line count = %d, want 1; output = %q", got, output.String())
	}
	if !strings.Contains(output.String(), `"component":"sd"`) {
		t.Fatalf("legacy logger fields were not preserved: %q", output.String())
	}
}

func TestNewConnectorLegacyNilUsesFallback(t *testing.T) {
	connector, err := NewConnector(nil, ETCDV3, "127.0.0.1:2379")
	if err != nil {
		t.Fatalf("NewConnector() error = %v", err)
	}
	if connector.logger != pklogging.Fallback() {
		t.Fatal("nil legacy logger did not use logging.Fallback")
	}
}
