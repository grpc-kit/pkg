package logging

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
		ok    bool
	}{
		{input: " debug ", want: slog.LevelDebug, ok: true},
		{input: "INFO", want: slog.LevelInfo, ok: true},
		{input: "warning", want: slog.LevelWarn, ok: true},
		{input: "warn", want: slog.LevelWarn, ok: true},
		{input: "error", want: slog.LevelError, ok: true},
		{input: "fatal", want: LevelFatal, ok: true},
		{input: "panic", want: LevelPanic, ok: true},
		{input: "trace", ok: false},
		{input: "", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, ok := ParseLevel(tt.input)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("ParseLevel(%q) = (%v, %v), want (%v, %v)", tt.input, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestParseFormat(t *testing.T) {
	tests := []struct {
		input string
		want  Format
		ok    bool
	}{
		{input: " text ", want: FormatText, ok: true},
		{input: "JSON", want: FormatJSON, ok: true},
		{input: "console", ok: false},
		{input: "", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, ok := ParseFormat(tt.input)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("ParseFormat(%q) = (%q, %v), want (%q, %v)", tt.input, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestNewJSONLogger(t *testing.T) {
	var output bytes.Buffer
	level := new(slog.LevelVar)
	level.Set(slog.LevelDebug)
	logger := New(&output, FormatJSON, &slog.HandlerOptions{Level: level}).With("service_name", "service.api")

	logger.LogAttrs(t.Context(), LevelFatal, "request failed", slog.String("request_id", "request-test"))

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode log output: %v", err)
	}
	if got := record[slog.LevelKey]; got != "fatal" {
		t.Errorf("level = %v, want fatal", got)
	}
	if got := record[slog.MessageKey]; got != "request failed" {
		t.Errorf("msg = %v, want request failed", got)
	}
	if got := record["service_name"]; got != "service.api" {
		t.Errorf("service_name = %v, want service.api", got)
	}
	if got := record["request_id"]; got != "request-test" {
		t.Errorf("request_id = %v, want request-test", got)
	}
}

func TestNewTextLogger(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output, FormatText, nil).With("service_name", "service.api")

	logger.InfoContext(t.Context(), "request complete", "request_id", "request-test")

	for _, want := range []string{
		"level=info",
		`msg="request complete"`,
		"service_name=service.api",
		"request_id=request-test",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("text output %q does not contain %q", output.String(), want)
		}
	}
}

func TestLevelVarUpdates(t *testing.T) {
	level := new(slog.LevelVar)
	level.Set(slog.LevelError)
	logger := New(io.Discard, FormatJSON, &slog.HandlerOptions{Level: level})

	if logger.Enabled(t.Context(), slog.LevelInfo) {
		t.Error("info enabled at error threshold")
	}
	level.Set(slog.LevelDebug)
	if !logger.Enabled(t.Context(), slog.LevelDebug) {
		t.Error("debug disabled after LevelVar update")
	}
}

func TestNewHandlerChainsReplaceAttr(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output, FormatJSON, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
			if attr.Key == "secret" {
				return slog.Attr{}
			}
			return attr
		},
	})

	logger.InfoContext(t.Context(), "message", "secret", "hidden", "visible", true)

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode log output: %v", err)
	}
	if _, ok := record["secret"]; ok {
		t.Error("secret attribute was not removed")
	}
	if got := record["visible"]; got != true {
		t.Errorf("visible = %v, want true", got)
	}
}

func TestNewHandlerProtectsReservedKeys(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output, FormatJSON, &slog.HandlerOptions{AddSource: true})

	logger.InfoContext(t.Context(), "actual message",
		slog.String(slog.TimeKey, "custom time"),
		slog.String(slog.LevelKey, "custom level"),
		slog.String(slog.MessageKey, "custom message"),
		slog.String(slog.SourceKey, "custom source"),
	)

	for _, key := range []string{slog.TimeKey, slog.LevelKey, slog.MessageKey, slog.SourceKey} {
		needle := []byte(`"` + key + `":`)
		if got := bytes.Count(output.Bytes(), needle); got != 1 {
			t.Errorf("reserved key %q occurred %d times, want 1; output: %s", key, got, output.Bytes())
		}
	}

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode log output: %v", err)
	}
	if got := record["fields.time"]; got != "custom time" {
		t.Errorf("fields.time = %v, want custom time", got)
	}
	if got := record["fields.level"]; got != "custom level" {
		t.Errorf("fields.level = %v, want custom level", got)
	}
	if got := record["fields.msg"]; got != "custom message" {
		t.Errorf("fields.msg = %v, want custom message", got)
	}
	if got := record["fields.source"]; got != "custom source" {
		t.Errorf("fields.source = %v, want custom source", got)
	}
}

func TestFallbackPolicy(t *testing.T) {
	logger := Fallback()
	if logger == nil {
		t.Fatal("Fallback returned nil")
	}
	if logger != Fallback() {
		t.Fatal("Fallback did not return the shared logger")
	}
	if logger.Enabled(t.Context(), slog.LevelDebug) {
		t.Error("fallback enabled debug, want disabled")
	}
	if !logger.Enabled(t.Context(), slog.LevelInfo) {
		t.Error("fallback disabled info, want enabled")
	}
	if got := OrFallback(nil); got != logger {
		t.Error("OrFallback(nil) did not use Fallback")
	}
}

func TestLoggerConcurrentUse(t *testing.T) {
	level := new(slog.LevelVar)
	level.Set(slog.LevelDebug)
	logger := New(io.Discard, FormatJSON, &slog.HandlerOptions{Level: level})
	ctx := t.Context()
	var wait sync.WaitGroup
	wait.Go(func() {
		for update := range 100 {
			if update%2 == 0 {
				level.Set(slog.LevelInfo)
			} else {
				level.Set(slog.LevelDebug)
			}
		}
	})
	for worker := range 16 {
		wait.Go(func() {
			for message := range 100 {
				logger.InfoContext(ctx, "concurrent", "worker", worker, "message", message)
			}
		})
	}
	wait.Wait()
}

func BenchmarkSlogJSON(b *testing.B) {
	logger := New(io.Discard, FormatJSON, &slog.HandlerOptions{Level: slog.LevelInfo}).With("service_name", "service.api")
	b.ReportAllocs()

	for b.Loop() {
		logger.With("request_id", "request-test").Info("baseline message")
	}
}

func BenchmarkSlogDisabledDebug(b *testing.B) {
	logger := New(io.Discard, FormatJSON, &slog.HandlerOptions{Level: slog.LevelInfo}).With("service_name", "service.api")
	b.ReportAllocs()

	for b.Loop() {
		logger.Debug("disabled baseline message")
	}
}

func BenchmarkSlogText(b *testing.B) {
	logger := New(io.Discard, FormatText, &slog.HandlerOptions{Level: slog.LevelInfo}).With("service_name", "service.api")
	b.ReportAllocs()

	for b.Loop() {
		logger.With("request_id", "request-test").Info("baseline message")
	}
}
