package rpc

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc"
)

type serverContextKey struct{}

type serverCaptureHandler struct {
	contextValue any
	message      string
}

func (*serverCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *serverCaptureHandler) Handle(ctx context.Context, record slog.Record) error {
	h.contextValue = ctx.Value(serverContextKey{})
	h.message = record.Message
	return nil
}

func (h *serverCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *serverCaptureHandler) WithGroup(string) slog.Handler      { return h }

func TestStartBackgroundRejectsCanceledContextBeforeListening(t *testing.T) {
	config := NewConfig(slog.New(slog.DiscardHandler))
	config.GRPCAddress = "invalid address"
	server := NewServer(config)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := server.StartBackground(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("StartBackground() error = %v, want context.Canceled", err)
	}
}

func TestStartBackgroundCancellationStopsGRPCDuringGatewayWait(t *testing.T) {
	config := NewConfig(slog.New(slog.DiscardHandler))
	config.GRPCAddress = "127.0.0.1:0"
	config.HTTPAddress = "127.0.0.1:0"
	server := NewServer(config)
	if err := server.RegisterGateway(http.NewServeMux()); err != nil {
		t.Fatalf("RegisterGateway() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	startedAt := time.Now()
	err := server.StartBackground(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("StartBackground() error = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(startedAt); elapsed >= time.Second {
		t.Fatalf("StartBackground() cancellation took %v, want less than 1s", elapsed)
	}

	if err := server.Server().Serve(rejectedListener{}); !errors.Is(err, grpc.ErrServerStopped) {
		t.Fatalf("Serve() after canceled startup error = %v, want grpc.ErrServerStopped", err)
	}
}

func TestStartBackgroundDisabledGRPCLogUsesContext(t *testing.T) {
	handler := &serverCaptureHandler{}
	config := NewConfig(slog.New(handler))
	config.GRPCAddress = "127.0.0.1:0"
	config.DisableGRPCServer = true
	server := NewServer(config)
	ctx := context.WithValue(t.Context(), serverContextKey{}, "startup")

	if err := server.StartBackground(ctx); err != nil {
		t.Fatalf("StartBackground() error = %v", err)
	}
	if handler.contextValue != "startup" {
		t.Errorf("log context value = %v, want startup", handler.contextValue)
	}
	if handler.message != "Disable gRPC server" {
		t.Errorf("log message = %q, want %q", handler.message, "Disable gRPC server")
	}
}

type rejectedListener struct{}

func (rejectedListener) Accept() (net.Conn, error) { return nil, errors.New("unexpected Accept call") }
func (rejectedListener) Close() error              { return nil }
func (rejectedListener) Addr() net.Addr            { return rejectedAddr("rejected") }

type rejectedAddr string

func (a rejectedAddr) Network() string { return string(a) }
func (a rejectedAddr) String() string  { return string(a) }
