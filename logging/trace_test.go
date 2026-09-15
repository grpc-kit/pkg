package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestTraceContextHandlerInjectsValidSpanContext(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output, FormatJSON, nil)
	ctx, traceID, spanID := validTraceContext(t.Context())

	logger.InfoContext(ctx, "request complete")

	record := decodeLogRecord(t, output.Bytes())
	if got := record[traceIDKey]; got != traceID.String() {
		t.Errorf("trace_id = %v, want %s", got, traceID)
	}
	if got := record[spanIDKey]; got != spanID.String() {
		t.Errorf("span_id = %v, want %s", got, spanID)
	}
}

func TestTraceContextHandlerOmitsInvalidSpanContext(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output, FormatJSON, nil)

	logger.InfoContext(t.Context(), "request complete")

	record := decodeLogRecord(t, output.Bytes())
	if _, ok := record[traceIDKey]; ok {
		t.Errorf("invalid SpanContext emitted trace_id: %v", record[traceIDKey])
	}
	if _, ok := record[spanIDKey]; ok {
		t.Errorf("invalid SpanContext emitted span_id: %v", record[spanIDKey])
	}
}

func TestTraceContextHandlerPreservesExplicitFields(t *testing.T) {
	tests := []struct {
		name   string
		logger func(*bytes.Buffer) *slog.Logger
		log    func(context.Context, *slog.Logger)
	}{
		{
			name: "record attrs",
			logger: func(output *bytes.Buffer) *slog.Logger {
				return New(output, FormatJSON, nil)
			},
			log: func(ctx context.Context, logger *slog.Logger) {
				logger.InfoContext(ctx, "request complete", traceIDKey, "caller-trace", spanIDKey, "caller-span")
			},
		},
		{
			name: "bound attrs",
			logger: func(output *bytes.Buffer) *slog.Logger {
				return New(output, FormatJSON, nil).With(traceIDKey, "caller-trace", spanIDKey, "caller-span")
			},
			log: func(ctx context.Context, logger *slog.Logger) {
				logger.InfoContext(ctx, "request complete")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := tt.logger(&output)
			ctx, _, _ := validTraceContext(t.Context())

			tt.log(ctx, logger)

			record := decodeLogRecord(t, output.Bytes())
			if got := record[traceIDKey]; got != "caller-trace" {
				t.Errorf("trace_id = %v, want caller-trace", got)
			}
			if got := record[spanIDKey]; got != "caller-span" {
				t.Errorf("span_id = %v, want caller-span", got)
			}
		})
	}
}

func BenchmarkTraceContextHandler(b *testing.B) {
	logger := New(io.Discard, FormatJSON, &slog.HandlerOptions{Level: slog.LevelInfo}).With(
		slog.String("service_name", "service.api"),
	)

	b.Run("without span context", func(b *testing.B) {
		ctx := b.Context()
		b.ReportAllocs()
		for b.Loop() {
			logger.InfoContext(ctx, "baseline message", slog.String("request_id", "request-test"))
		}
	})

	b.Run("with span context", func(b *testing.B) {
		ctx, _, _ := validTraceContext(b.Context())
		b.ReportAllocs()
		for b.Loop() {
			logger.InfoContext(ctx, "baseline message", slog.String("request_id", "request-test"))
		}
	})
}

func validTraceContext(ctx context.Context) (context.Context, trace.TraceID, trace.SpanID) {
	traceID := trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	spanID := trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8}
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID,
		SpanID:  spanID,
	})
	return trace.ContextWithSpanContext(ctx, spanContext), traceID, spanID
}

func decodeLogRecord(t *testing.T, data []byte) map[string]any {
	t.Helper()
	record := make(map[string]any)
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("decode log output %q: %v", data, err)
	}
	return record
}
