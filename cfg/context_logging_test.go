package cfg

import (
	"context"
	"log/slog"
	"testing"
)

type contextCaptureHandler struct {
	context context.Context
}

func (h *contextCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *contextCaptureHandler) Handle(ctx context.Context, _ slog.Record) error {
	h.context = ctx
	return nil
}

func (h *contextCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *contextCaptureHandler) WithGroup(string) slog.Handler      { return h }

func TestRunAutoBridgePropagatesContextToLogs(t *testing.T) {
	type contextKey struct{}
	handler := &contextCaptureHandler{}
	config := newMCPRuntimeConfig(t)
	config.logger = slog.New(handler)
	config.rpcConfig = nil
	ctx := context.WithValue(t.Context(), contextKey{}, "registration-context")

	config.runAutoBridge(ctx)

	if got := handler.context.Value(contextKey{}); got != "registration-context" {
		t.Fatalf("logged context value = %v, want registration-context", got)
	}
}
