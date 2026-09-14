package errs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
)

type contextCaptureHandler struct {
	context context.Context
	records []slog.Record
}

func (h *contextCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *contextCaptureHandler) Handle(ctx context.Context, record slog.Record) error {
	h.context = ctx
	h.records = append(h.records, record.Clone())
	return nil
}

func (h *contextCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *contextCaptureHandler) WithGroup(string) slog.Handler      { return h }

func TestWithLoggerWritesOnceAndAddsDebugInfo(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	status := New(codes.Internal, "internal")
	testErr := errors.New("boom")

	got := status.WithLogger(t.Context(), logger, "operation failed: %v", testErr)

	if got != status {
		t.Fatal("WithLogger did not return its receiver")
	}
	if count := strings.Count(output.String(), "\n"); count != 1 {
		t.Fatalf("log line count = %d, want 1; output = %q", count, output.String())
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode JSON log: %v", err)
	}
	if got := record["msg"]; got != "operation failed: boom" {
		t.Fatalf("formatted message = %v, want operation failed: boom", got)
	}
	if got := record["error"]; got != testErr.Error() {
		t.Fatalf("error attr = %v, want %q", got, testErr.Error())
	}
	assertDebugInfo(t, status, "operation failed: boom")
}

func TestWithLoggerInfoLevelOmitsDebugInfo(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelInfo}))
	status := New(codes.Internal, "internal")

	status.WithLogger(t.Context(), logger, "operation failed: %v", errors.New("boom"))

	if len(status.anyType) != 0 {
		t.Fatalf("debug details = %d, want 0", len(status.anyType))
	}
}

func TestWithLoggerNilUsesFallback(t *testing.T) {
	status := New(codes.Internal, "internal")
	status.WithLogger(t.Context(), nil, "operation failed: %v", errors.New("boom"))

	if len(status.anyType) != 0 {
		t.Fatalf("debug details = %d, want 0", len(status.anyType))
	}
}

func TestWithLoggerPropagatesContext(t *testing.T) {
	type contextKey struct{}
	handler := &contextCaptureHandler{}
	logger := slog.New(handler)
	ctx := context.WithValue(t.Context(), contextKey{}, "request-context")
	status := New(codes.Internal, "internal")
	testErr := errors.New("boom")

	status.WithLogger(ctx, logger, "operation failed: %v", testErr)

	if got := handler.context.Value(contextKey{}); got != "request-context" {
		t.Fatalf("logged context value = %v, want request-context", got)
	}
	if len(handler.records) != 1 {
		t.Fatalf("record count = %d, want 1", len(handler.records))
	}
	assertTypedErrorAttr(t, handler.records[0], testErr)
	assertDebugInfo(t, status, "operation failed: boom")
}

func assertTypedErrorAttr(t *testing.T, record slog.Record, want error) {
	t.Helper()
	found := false
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key != "error" {
			return true
		}
		found = true
		got, ok := attr.Value.Any().(error)
		if !ok || !errors.Is(got, want) {
			t.Errorf("error attr = %#v, want typed error %v", attr.Value.Any(), want)
		}
		return false
	})
	if !found {
		t.Error("error attr not found")
	}
}

func assertDebugInfo(t *testing.T, status *Status, want string) {
	t.Helper()
	if len(status.anyType) != 1 {
		t.Fatalf("debug details = %d, want 1", len(status.anyType))
	}
	detail, ok := status.anyType[0].(*errdetails.DebugInfo)
	if !ok {
		t.Fatalf("debug detail type = %T, want *errdetails.DebugInfo", status.anyType[0])
	}
	if detail.Detail != want {
		t.Fatalf("debug detail = %q, want %q", detail.Detail, want)
	}
}
