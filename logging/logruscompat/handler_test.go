package logruscompat

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	pklogging "github.com/grpc-kit/pkg/logging"
	"github.com/sirupsen/logrus"
)

type contextKey struct{}

func TestHandlerPreservesFieldsGroupsErrorsAndContext(t *testing.T) {
	var output bytes.Buffer
	baseContext := context.WithValue(context.Background(), contextKey{}, "base")
	logger, hook := newCapturedLogger(&output, logrus.DebugLevel)
	entry := logrus.NewEntry(logger).WithContext(baseContext).WithField("service_name", "service.api")
	slogger := NewLogger(entry).With("component", "rpc").WithGroup("request")
	wantErr := errors.New("request failed")
	explicitContext := context.WithValue(t.Context(), contextKey{}, "explicit")

	slogger.Info("uses base context", "method", "List")
	slogger.ErrorContext(explicitContext, "uses explicit context", slog.Any("error", wantErr), slog.Group("peer", "ip", "127.0.0.1"))

	entries := hook.entries()
	if len(entries) != 2 {
		t.Fatalf("hook entries = %d, want 2", len(entries))
	}
	if got := entries[0].Context.Value(contextKey{}); got != "base" {
		t.Errorf("base context value = %v, want base", got)
	}
	if got := entries[1].Context.Value(contextKey{}); got != "explicit" {
		t.Errorf("explicit context value = %v, want explicit", got)
	}
	if got := entries[1].Data["service_name"]; got != "service.api" {
		t.Errorf("service_name = %v, want service.api", got)
	}
	if got := entries[1].Data["component"]; got != "rpc" {
		t.Errorf("component = %v, want rpc", got)
	}
	if !errors.Is(entries[1].Data["request.error"].(error), wantErr) {
		t.Errorf("request.error = %v, want wrapped target", entries[1].Data["request.error"])
	}
	if got := entries[1].Data["request.peer.ip"]; got != "127.0.0.1" {
		t.Errorf("request.peer.ip = %v, want 127.0.0.1", got)
	}

	lines := bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("output lines = %d, want 2", len(lines))
	}
	var record map[string]any
	if err := json.Unmarshal(lines[1], &record); err != nil {
		t.Fatalf("decode log output: %v", err)
	}
	if got := record["request.error"]; got != wantErr.Error() {
		t.Errorf("serialized error = %v, want %q", got, wantErr)
	}
}

func TestHandlerPreservesRecordTime(t *testing.T) {
	logger, hook := newCapturedLogger(io.Discard, logrus.DebugLevel)
	handler := NewHandler(logrus.NewEntry(logger))
	want := time.Date(2026, time.September, 13, 8, 30, 0, 123, time.UTC)
	record := slog.NewRecord(want, slog.LevelInfo, "fixed time", 0)

	if err := handler.Handle(t.Context(), record); err != nil {
		t.Fatalf("Handle returned error: %v", err)
	}

	entries := hook.entries()
	if len(entries) != 1 {
		t.Fatalf("hook entries = %d, want 1", len(entries))
	}
	if !entries[0].Time.Equal(want) {
		t.Errorf("record time = %v, want %v", entries[0].Time, want)
	}
}

func TestHandlerPreservesAttributeTypes(t *testing.T) {
	logger, hook := newCapturedLogger(io.Discard, logrus.DebugLevel)
	slogger := NewLogger(logrus.NewEntry(logger))
	wantDuration := 1500 * time.Millisecond

	slogger.Info("typed fields",
		"string", "value",
		"number", 42,
		"bool", true,
		"duration", wantDuration,
		"nil", nil,
		slog.Group("empty"),
	)

	entries := hook.entries()
	if len(entries) != 1 {
		t.Fatalf("hook entries = %d, want 1", len(entries))
	}
	fields := entries[0].Data
	if got := fields["string"]; got != "value" {
		t.Errorf("string = %v, want value", got)
	}
	if got := fields["number"]; got != int64(42) {
		t.Errorf("number = %T(%v), want int64(42)", got, got)
	}
	if got := fields["bool"]; got != true {
		t.Errorf("bool = %v, want true", got)
	}
	if got := fields["duration"]; got != wantDuration {
		t.Errorf("duration = %v, want %v", got, wantDuration)
	}
	if got, exists := fields["nil"]; !exists || got != nil {
		t.Errorf("nil = %v (exists %v), want nil field", got, exists)
	}
	if _, exists := fields["empty"]; exists {
		t.Error("empty group produced a field")
	}
}

func TestHandlerLevelMappingAndFiltering(t *testing.T) {
	logger, hook := newCapturedLogger(io.Discard, logrus.WarnLevel)
	slogger := NewLogger(logrus.NewEntry(logger))

	if slogger.Enabled(t.Context(), slog.LevelInfo) {
		t.Error("info enabled at logrus warn level")
	}
	if !slogger.Enabled(t.Context(), slog.LevelWarn) {
		t.Error("warn disabled at logrus warn level")
	}

	logger.SetLevel(logrus.TraceLevel)
	slogger.Log(t.Context(), pklogging.LevelFatal, "fatal record")

	entries := hook.entries()
	if len(entries) != 1 {
		t.Fatalf("hook entries = %d, want 1", len(entries))
	}
	if entries[0].Level != logrus.FatalLevel {
		t.Errorf("fatal level = %v, want %v", entries[0].Level, logrus.FatalLevel)
	}
}

func TestHandlerPanicLevelDoesNotPanic(t *testing.T) {
	logger, hook := newCapturedLogger(io.Discard, logrus.TraceLevel)
	slogger := NewLogger(logrus.NewEntry(logger))

	slogger.Log(t.Context(), pklogging.LevelPanic, "panic severity record")

	entries := hook.entries()
	if len(entries) != 1 {
		t.Fatalf("hook entries = %d, want 1", len(entries))
	}
	if entries[0].Level != logrus.PanicLevel {
		t.Errorf("panic level = %v, want %v", entries[0].Level, logrus.PanicLevel)
	}
}

func TestHandlerDerivationsAreImmutable(t *testing.T) {
	logger, hook := newCapturedLogger(io.Discard, logrus.DebugLevel)
	base := NewLogger(logrus.NewEntry(logger))
	derived := base.With("scope", "derived")

	base.Info("base")
	derived.Info("derived")

	entries := hook.entries()
	if _, exists := entries[0].Data["scope"]; exists {
		t.Error("derived attribute leaked into base handler")
	}
	if got := entries[1].Data["scope"]; got != "derived" {
		t.Errorf("derived scope = %v, want derived", got)
	}
}

func TestNilEntryUsesFallback(t *testing.T) {
	if got := NewLogger(nil); got != pklogging.Fallback() {
		t.Error("NewLogger(nil) did not return logging.Fallback")
	}
	if got := NewLogger(&logrus.Entry{}); got != pklogging.Fallback() {
		t.Error("NewLogger(entry without Logger) did not return logging.Fallback")
	}
}

func TestHandlerConcurrentUse(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	logger.SetLevel(logrus.DebugLevel)
	slogger := NewLogger(logrus.NewEntry(logger).WithField("service_name", "service.api"))

	ctx := t.Context()
	var wait sync.WaitGroup
	for worker := range 16 {
		wait.Go(func() {
			derived := slogger.With("worker", worker).WithGroup("request")
			for message := range 100 {
				derived.InfoContext(ctx, "concurrent", "message", message)
			}
		})
	}
	wait.Wait()
}

func BenchmarkLogrusCompatJSON(b *testing.B) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(logrus.InfoLevel)
	slogger := NewLogger(logrus.NewEntry(logger).WithField("service_name", "service.api"))
	b.ReportAllocs()

	for b.Loop() {
		slogger.With("request_id", "request-test").Info("baseline message")
	}
}

func BenchmarkLogrusCompatDisabledDebug(b *testing.B) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	logger.SetLevel(logrus.InfoLevel)
	slogger := NewLogger(logrus.NewEntry(logger).WithField("service_name", "service.api"))
	b.ReportAllocs()

	for b.Loop() {
		slogger.Debug("disabled baseline message")
	}
}

type captureHook struct {
	mu       sync.Mutex
	captured []*logrus.Entry
}

func (h *captureHook) Levels() []logrus.Level {
	return logrus.AllLevels
}

func (h *captureHook) Fire(entry *logrus.Entry) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	captured := entry.Dup()
	captured.Level = entry.Level
	captured.Message = entry.Message
	h.captured = append(h.captured, captured)
	return nil
}

func (h *captureHook) entries() []*logrus.Entry {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*logrus.Entry(nil), h.captured...)
}

func newCapturedLogger(output io.Writer, level logrus.Level) (*logrus.Logger, *captureHook) {
	logger := logrus.New()
	logger.SetOutput(output)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetLevel(level)
	hook := new(captureHook)
	logger.AddHook(hook)
	return logger, hook
}
