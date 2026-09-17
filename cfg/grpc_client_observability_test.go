package cfg

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/test/bufconn"
)

const clientObservabilityTestBufferSize = 1024 * 1024

type clientObservabilityTestStatsHandler struct {
	rpcEvents atomic.Int64
}

func (h *clientObservabilityTestStatsHandler) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return ctx
}

func (h *clientObservabilityTestStatsHandler) HandleRPC(_ context.Context, _ stats.RPCStats) {
	h.rpcEvents.Add(1)
}

func (h *clientObservabilityTestStatsHandler) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context {
	return ctx
}

func (h *clientObservabilityTestStatsHandler) HandleConn(context.Context, stats.ConnStats) {}

func TestGetClientDialOptionConfiguresOpenTelemetry(t *testing.T) {
	tests := []struct {
		name           string
		enabled        bool
		filteredMethod string
		invoke         func(context.Context, healthpb.HealthClient) error
		wantSpanSuffix string
	}{
		{
			name:           "unary rpc",
			enabled:        true,
			invoke:         invokeHealthCheck,
			wantSpanSuffix: "/Check",
		},
		{
			name:           "streaming rpc",
			enabled:        true,
			invoke:         invokeHealthWatch,
			wantSpanSuffix: "/Watch",
		},
		{
			name:           "filtered rpc",
			enabled:        true,
			filteredMethod: "Check",
			invoke:         invokeHealthCheck,
		},
		{
			name:   "observability disabled",
			invoke: invokeHealthCheck,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spanRecorder := tracetest.NewSpanRecorder()
			tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spanRecorder))
			previousTracerProvider := otel.GetTracerProvider()
			otel.SetTracerProvider(tracerProvider)
			t.Cleanup(func() {
				otel.SetTracerProvider(previousTracerProvider)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := tracerProvider.Shutdown(ctx); err != nil {
					t.Errorf("shutdown tracer provider: %v", err)
				}
			})

			config := newClientObservabilityTestConfig(tt.enabled, tt.filteredMethod)
			customStatsHandler := &clientObservabilityTestStatsHandler{}
			client := newClientObservabilityTestHealthClient(t, config, customStatsHandler)

			if err := tt.invoke(t.Context(), client); err != nil {
				t.Fatalf("invoke health RPC: %v", err)
			}

			if got := customStatsHandler.rpcEvents.Load(); got == 0 {
				t.Fatal("custom stats handler did not receive RPC events")
			}

			spans := spanRecorder.Ended()
			if tt.wantSpanSuffix == "" {
				if len(spans) != 0 {
					t.Fatalf("ended spans = %d, want 0", len(spans))
				}
				return
			}

			if len(spans) != 1 {
				t.Fatalf("ended spans = %d, want 1", len(spans))
			}
			if got := spans[0].Name(); !strings.HasSuffix(got, tt.wantSpanSuffix) {
				t.Fatalf("span name = %q, want suffix %q", got, tt.wantSpanSuffix)
			}
			if got := spans[0].SpanKind(); got != trace.SpanKindClient {
				t.Fatalf("span kind = %v, want %v", got, trace.SpanKindClient)
			}
		})
	}
}

func TestGetClientStreamInterceptorRemainsExtensionPoint(t *testing.T) {
	config := &LocalConfig{}
	if got := config.GetClientStreamInterceptor(); len(got) != 0 {
		t.Fatalf("stream interceptors = %d, want 0", len(got))
	}
}

func newClientObservabilityTestConfig(enabled bool, filteredMethod string) *LocalConfig {
	traceConfig := &TelemetryTrace{}
	if filteredMethod != "" {
		traceConfig.Filters = append(traceConfig.Filters, struct {
			Method  string `mapstructure:"method"`
			URLPath string `mapstructure:"url_path"`
		}{Method: filteredMethod})
	}

	return &LocalConfig{Observables: &ObservablesConfig{
		Enable: &enabled,
		Telemetry: &TelemetryConfig{
			Traces: traceConfig,
		},
	}}
}

func newClientObservabilityTestHealthClient(
	t *testing.T,
	config *LocalConfig,
	customStatsHandler stats.Handler,
) healthpb.HealthClient {
	t.Helper()

	listener := bufconn.Listen(clientObservabilityTestBufferSize)
	server := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		if err := <-serveErr; err != nil {
			t.Errorf("serve health server: %v", err)
		}
	})

	dialOptions := config.GetClientDialOption(
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithStatsHandler(customStatsHandler),
	)
	conn, err := grpc.NewClient("passthrough:///bufconn", dialOptions...)
	if err != nil {
		t.Fatalf("create gRPC client: %v", err)
	}
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("close gRPC client: %v", err)
		}
	})

	return healthpb.NewHealthClient(conn)
}

func invokeHealthCheck(ctx context.Context, client healthpb.HealthClient) error {
	_, err := client.Check(ctx, &healthpb.HealthCheckRequest{})
	return err
}

func invokeHealthWatch(ctx context.Context, client healthpb.HealthClient) error {
	ctx, cancel := context.WithCancel(ctx)
	stream, err := client.Watch(ctx, &healthpb.HealthCheckRequest{})
	if err != nil {
		cancel()
		return err
	}
	if _, err := stream.Recv(); err != nil {
		cancel()
		return err
	}
	cancel()
	_, _ = stream.Recv()
	return nil
}
