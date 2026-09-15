package sd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/resolver"

	pklogging "github.com/grpc-kit/pkg/logging"
)

type capturedSDLog struct {
	contextValue any
	level        slog.Level
	message      string
	attrs        map[string]slog.Value
}

type sdCaptureHandler struct {
	records *[]capturedSDLog
}

func (h *sdCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *sdCaptureHandler) Handle(ctx context.Context, record slog.Record) error {
	attrs := make(map[string]slog.Value)
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value
		return true
	})
	*h.records = append(*h.records, capturedSDLog{
		contextValue: ctx.Value(sdContextKey{}),
		level:        record.Level,
		message:      record.Message,
		attrs:        attrs,
	})
	return nil
}

func (h *sdCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *sdCaptureHandler) WithGroup(string) slog.Handler      { return h }

type sdContextKey struct{}

func TestSDStructuredFailureLogs(t *testing.T) {
	testErr := errors.New("etcd failure")
	tests := []struct {
		name      string
		log       func(context.Context, *slog.Logger)
		wantMsg   string
		wantEvent string
	}{
		{
			name: "registration retry",
			log: func(ctx context.Context, logger *slog.Logger) {
				logRegistrationRetry(ctx, logger, testErr)
			},
			wantMsg:   "service registration failed; retrying",
			wantEvent: eventRegistrationRetry,
		},
		{
			name: "resolver lookup",
			log: func(ctx context.Context, logger *slog.Logger) {
				logResolverLookupFailed(ctx, logger, testErr)
			},
			wantMsg:   "failed to resolve service; using last known addresses",
			wantEvent: eventResolverLookupFailed,
		},
		{
			name: "resolver state restore",
			log: func(ctx context.Context, logger *slog.Logger) {
				logResolverStateRestoreFailed(ctx, logger, testErr)
			},
			wantMsg:   "failed to restore last resolver state",
			wantEvent: eventResolverStateRestoreFailed,
		},
		{
			name: "resolver state update",
			log: func(ctx context.Context, logger *slog.Logger) {
				logResolverStateUpdateFailed(ctx, logger, 3, testErr)
			},
			wantMsg:   "failed to update resolver state",
			wantEvent: eventResolverStateUpdateFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var records []capturedSDLog
			logger := slog.New(&sdCaptureHandler{records: &records})
			ctx := context.WithValue(t.Context(), sdContextKey{}, tt.name)

			tt.log(ctx, logger)

			if len(records) != 1 {
				t.Fatalf("record count = %d, want 1", len(records))
			}
			record := records[0]
			if record.contextValue != tt.name {
				t.Errorf("context value = %v, want %q", record.contextValue, tt.name)
			}
			if record.level != slog.LevelError {
				t.Errorf("level = %v, want error", record.level)
			}
			if record.message != tt.wantMsg {
				t.Errorf("message = %q, want %q", record.message, tt.wantMsg)
			}
			if got := record.attrs["event"].String(); got != tt.wantEvent {
				t.Errorf("event = %q, want %q", got, tt.wantEvent)
			}
			gotErr, ok := record.attrs["error"].Any().(error)
			if !ok || !errors.Is(gotErr, testErr) {
				t.Errorf("error attr = %#v, want typed test error", record.attrs["error"].Any())
			}
			if tt.wantEvent == eventResolverStateUpdateFailed {
				if got := record.attrs["address_count"].Int64(); got != 3 {
					t.Errorf("address_count = %d, want 3", got)
				}
			}
		})
	}
}

func TestSDStructuredLifecycleLogs(t *testing.T) {
	var records []capturedSDLog
	logger := slog.New(&sdCaptureHandler{records: &records})
	ctx := context.WithValue(t.Context(), sdContextKey{}, "lifecycle")

	logRegistrationSucceeded(ctx, logger, 30, 101)
	logKeepaliveReceived(ctx, logger, 29, 101)
	logResolverStateUpdated(ctx, logger, 2)

	if len(records) != 3 {
		t.Fatalf("record count = %d, want 3", len(records))
	}
	wants := []struct {
		message      string
		event        string
		contextValue any
	}{
		{"registered service endpoint", eventRegistrationSucceeded, "lifecycle"},
		{"received service lease keepalive", eventKeepaliveReceived, "lifecycle"},
		{"updated resolver state", eventResolverStateUpdated, "lifecycle"},
	}
	for index, want := range wants {
		record := records[index]
		if record.level != slog.LevelDebug {
			t.Errorf("record[%d] level = %v, want debug", index, record.level)
		}
		if record.message != want.message {
			t.Errorf("record[%d] message = %q, want %q", index, record.message, want.message)
		}
		if got := record.attrs["event"].String(); got != want.event {
			t.Errorf("record[%d] event = %q, want %q", index, got, want.event)
		}
		if record.contextValue != want.contextValue {
			t.Errorf("record[%d] context value = %v, want %v", index, record.contextValue, want.contextValue)
		}
	}
	for _, index := range []int{0, 1} {
		if got := records[index].attrs["ttl_seconds"].Int64(); got != int64(30-index) {
			t.Errorf("record[%d] ttl_seconds = %d", index, got)
		}
		if got := records[index].attrs["lease_id"].Int64(); got != 101 {
			t.Errorf("record[%d] lease_id = %d, want 101", index, got)
		}
	}
	if got := records[2].attrs["address_count"].Int64(); got != 2 {
		t.Errorf("address_count = %d, want 2", got)
	}
}

func TestSDStructuredLogJSONIncludesTraceWithoutContextSecrets(t *testing.T) {
	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, nil)
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 2, 3},
		SpanID:  trace.SpanID{4, 5, 6},
	})
	ctx := trace.ContextWithSpanContext(t.Context(), spanContext)
	ctx = context.WithValue(ctx, sdContextKey{}, "authorization-secret")

	logResolverLookupFailed(ctx, logger, errors.New("lookup failed"))

	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("JSON line count = %d, want 1; output=%q", got, output.String())
	}
	if strings.Contains(output.String(), "authorization-secret") {
		t.Fatalf("context-only sensitive value leaked into log: %q", output.String())
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode JSON log: %v", err)
	}
	for key, want := range map[string]string{
		"level":    "error",
		"msg":      "failed to resolve service; using last known addresses",
		"event":    eventResolverLookupFailed,
		"error":    "lookup failed",
		"trace_id": spanContext.TraceID().String(),
		"span_id":  spanContext.SpanID().String(),
	} {
		if got := record[key]; got != want {
			t.Errorf("%s = %v, want %q", key, got, want)
		}
	}
}

type sdTestClientConn struct {
	resolver.ClientConn
	state resolver.State
}

func (c *sdTestClientConn) UpdateState(state resolver.State) error {
	c.state = state
	return nil
}

func TestUpdateStateLogOmitsEndpointAndAddresses(t *testing.T) {
	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})
	clientConn := &sdTestClientConn{}
	client := &etcdv3Client{
		logger:      logger,
		mutexState:  new(sync.RWMutex),
		targetState: make(map[string]resolver.State),
	}
	endpoint := "payments?token=endpoint-secret"
	resolverClient := &etcdv3Resolver{
		client:   client,
		cc:       clientConn,
		endpoint: endpoint,
	}
	state := resolver.State{Addresses: []resolver.Address{
		{Addr: "user:password@10.0.0.1:443"},
		{Addr: "10.0.0.2:443"},
	}}
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 2, 3},
		SpanID:  trace.SpanID{4, 5, 6},
	})
	ctx := trace.ContextWithSpanContext(t.Context(), spanContext)

	if err := resolverClient.updateState(ctx, state); err != nil {
		t.Fatalf("updateState() error = %v", err)
	}
	if strings.Contains(output.String(), endpoint) || strings.Contains(output.String(), state.Addresses[0].Addr) {
		t.Fatalf("endpoint or address leaked into log: %q", output.String())
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode JSON log: %v", err)
	}
	if got := record["event"]; got != eventResolverStateUpdated {
		t.Errorf("event = %v, want %q", got, eventResolverStateUpdated)
	}
	if got := record["address_count"]; got != float64(2) {
		t.Errorf("address_count = %v, want 2", got)
	}
	if got := record["trace_id"]; got != spanContext.TraceID().String() {
		t.Errorf("trace_id = %v, want %q", got, spanContext.TraceID())
	}
	if len(clientConn.state.Addresses) != 2 {
		t.Errorf("updated address count = %d, want 2", len(clientConn.state.Addresses))
	}
}

func TestResolverCloseCancelsOnlyItsOwnLifecycle(t *testing.T) {
	parentCtx, cancelParent := context.WithCancel(t.Context())
	client := &etcdv3Client{lifecycleCtx: parentCtx}
	first, err := client.newResolver("first", &sdTestClientConn{})
	if err != nil {
		t.Fatalf("newResolver(first) error = %v", err)
	}
	second, err := client.newResolver("second", &sdTestClientConn{})
	if err != nil {
		t.Fatalf("newResolver(second) error = %v", err)
	}

	first.Close()
	first.Close()

	if !errors.Is(first.ctx.Err(), context.Canceled) {
		t.Fatalf("first resolver context error = %v, want context.Canceled", first.ctx.Err())
	}
	if err := second.ctx.Err(); err != nil {
		t.Fatalf("second resolver context error = %v, want nil", err)
	}

	cancelParent()
	if !errors.Is(second.ctx.Err(), context.Canceled) {
		t.Fatalf("second resolver context error = %v, want context.Canceled", second.ctx.Err())
	}
	if _, err := client.newResolver("third", &sdTestClientConn{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("newResolver(third) error = %v, want context.Canceled", err)
	}
}

func TestResolversUpdateIndependentClientConnections(t *testing.T) {
	client := &etcdv3Client{
		logger:      slog.New(slog.DiscardHandler),
		mutexState:  new(sync.RWMutex),
		targetState: make(map[string]resolver.State),
	}
	firstConn := &sdTestClientConn{}
	secondConn := &sdTestClientConn{}
	first := &etcdv3Resolver{client: client, cc: firstConn, endpoint: "first"}
	second := &etcdv3Resolver{client: client, cc: secondConn, endpoint: "second"}

	if err := first.updateState(t.Context(), resolver.State{Addresses: []resolver.Address{{Addr: "first:443"}}}); err != nil {
		t.Fatalf("first updateState() error = %v", err)
	}
	if err := second.updateState(t.Context(), resolver.State{Addresses: []resolver.Address{{Addr: "second:443"}}}); err != nil {
		t.Fatalf("second updateState() error = %v", err)
	}

	if got := firstConn.state.Addresses[0].Addr; got != "first:443" {
		t.Errorf("first resolver address = %q, want first:443", got)
	}
	if got := secondConn.state.Addresses[0].Addr; got != "second:443" {
		t.Errorf("second resolver address = %q, want second:443", got)
	}
}

func TestKeepaliveLogUsesOnlyLeaseMetadata(t *testing.T) {
	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})
	client := &etcdv3Client{logger: logger}
	responses := make(chan *clientv3.LeaseKeepAliveResponse, 1)
	responses <- &clientv3.LeaseKeepAliveResponse{ID: 101, TTL: 29}
	close(responses)

	if err := client.eatKeepAliveMessage(t.Context(), responses); err == nil {
		t.Fatal("eatKeepAliveMessage() error = nil, want closed-channel error")
	}
	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("log line count = %d, want 1; output=%q", got, output.String())
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode JSON log: %v", err)
	}
	if got := record["event"]; got != eventKeepaliveReceived {
		t.Errorf("event = %v, want %q", got, eventKeepaliveReceived)
	}
	if got := record["ttl_seconds"]; got != float64(29) {
		t.Errorf("ttl_seconds = %v, want 29", got)
	}
	if got := record["lease_id"]; got != float64(101) {
		t.Errorf("lease_id = %v, want 101", got)
	}
}
