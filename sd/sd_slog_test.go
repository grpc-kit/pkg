package sd

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	pklogging "github.com/grpc-kit/pkg/logging"
	"google.golang.org/grpc/resolver"
)

var (
	_ Registry          = (*etcdv3Client)(nil)
	_ resolver.Resolver = (*etcdv3Resolver)(nil)
)

func TestNewConnector(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	connector, err := NewConnector(logger, ETCDV3, "127.0.0.1:2379")
	if err != nil {
		t.Fatalf("NewConnector() error = %v", err)
	}
	if connector.logger != logger {
		t.Fatal("NewConnector did not retain the supplied logger")
	}
	if connector.Driver != ETCDV3 || connector.Hosts != "127.0.0.1:2379" {
		t.Fatalf("connector fields = (%d, %q), want (%d, %q)", connector.Driver, connector.Hosts, ETCDV3, "127.0.0.1:2379")
	}

	connector.logger.Info("native sd logger")
	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("native log line count = %d, want 1; output = %q", got, output.String())
	}
}

func TestNewConnectorNilUsesFallback(t *testing.T) {
	connector, err := NewConnector(nil, ETCDV3, "127.0.0.1:2379")
	if err != nil {
		t.Fatalf("NewConnector() error = %v", err)
	}
	if connector.logger != pklogging.Fallback() {
		t.Fatal("nil slog logger did not use logging.Fallback")
	}
}

func TestRegisterRejectsCanceledContext(t *testing.T) {
	connector, err := NewConnector(nil, ETCDV3, "127.0.0.1:2379")
	if err != nil {
		t.Fatalf("NewConnector() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	registry, err := Register(ctx, connector, "service", "127.0.0.1:10081", "{}", 30)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Register() error = %v, want context.Canceled", err)
	}
	if client, ok := registry.(*etcdv3Client); ok {
		if !errors.Is(client.lifecycleCtx.Err(), context.Canceled) {
			t.Errorf("lifecycle context error = %v, want context.Canceled", client.lifecycleCtx.Err())
		}
		if closeErr := client.client.Close(); closeErr != nil {
			t.Errorf("close etcd client: %v", closeErr)
		}
	}
}

func TestEtcdv3DeregisterUsesCanceledContext(t *testing.T) {
	connector, err := NewConnector(nil, ETCDV3, "127.0.0.1:2379")
	if err != nil {
		t.Fatalf("NewConnector() error = %v", err)
	}
	client, err := newEtcdv3Client(t.Context(), "service", "default", connector)
	if err != nil {
		t.Fatalf("newEtcdv3Client() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := client.client.Close(); closeErr != nil {
			t.Errorf("close etcd client: %v", closeErr)
		}
	})
	client.serviceName = "service"
	client.serviceAddr = "127.0.0.1:10081"
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := client.Deregister(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Deregister() error = %v, want context.Canceled", err)
	}
	if !errors.Is(client.lifecycleCtx.Err(), context.Canceled) {
		t.Fatalf("lifecycle context error = %v, want context.Canceled", client.lifecycleCtx.Err())
	}
}
