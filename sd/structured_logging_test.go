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
	if got := record["level"]; got != "debug" {
		t.Errorf("level = %v, want %q", got, "debug")
	}
	if got := record["msg"]; got != "updated resolver state" {
		t.Errorf("msg = %v, want %q", got, "updated resolver state")
	}
	if got := record["event"]; got != "sd_resolver_state_updated" {
		t.Errorf("event = %v, want %q", got, "sd_resolver_state_updated")
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
	if got := record["level"]; got != "debug" {
		t.Errorf("level = %v, want %q", got, "debug")
	}
	if got := record["msg"]; got != "received service lease keepalive" {
		t.Errorf("msg = %v, want %q", got, "received service lease keepalive")
	}
	if got := record["event"]; got != "sd_keepalive_received" {
		t.Errorf("event = %v, want %q", got, "sd_keepalive_received")
	}
	if got := record["ttl_seconds"]; got != float64(29) {
		t.Errorf("ttl_seconds = %v, want 29", got)
	}
	if got := record["lease_id"]; got != float64(101) {
		t.Errorf("lease_id = %v, want 101", got)
	}
}
