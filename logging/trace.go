package logging

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel/trace"
)

const (
	traceIDKey = "trace_id"
	spanIDKey  = "span_id"
)

// traceContextHandler adds OpenTelemetry trace correlation fields when the
// logging context contains a valid SpanContext. Explicit caller fields win.
type traceContextHandler struct {
	handler    slog.Handler
	hasTraceID bool
	hasSpanID  bool
}

func (h *traceContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *traceContextHandler) Handle(ctx context.Context, record slog.Record) error {
	spanContext := trace.SpanContextFromContext(ctx)
	if !spanContext.IsValid() {
		return h.handler.Handle(ctx, record)
	}

	hasTraceID, hasSpanID := h.hasTraceID, h.hasSpanID
	record.Attrs(func(attr slog.Attr) bool {
		attrTraceID, attrSpanID := traceKeys(attr)
		hasTraceID = hasTraceID || attrTraceID
		hasSpanID = hasSpanID || attrSpanID
		return !(hasTraceID && hasSpanID)
	})

	if !hasTraceID {
		record.AddAttrs(slog.String(traceIDKey, spanContext.TraceID().String()))
	}
	if !hasSpanID {
		record.AddAttrs(slog.String(spanIDKey, spanContext.SpanID().String()))
	}

	return h.handler.Handle(ctx, record)
}

func (h *traceContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	hasTraceID, hasSpanID := h.hasTraceID, h.hasSpanID
	for _, attr := range attrs {
		attrTraceID, attrSpanID := traceKeys(attr)
		hasTraceID = hasTraceID || attrTraceID
		hasSpanID = hasSpanID || attrSpanID
	}
	return &traceContextHandler{
		handler:    h.handler.WithAttrs(attrs),
		hasTraceID: hasTraceID,
		hasSpanID:  hasSpanID,
	}
}

func (h *traceContextHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &traceContextHandler{
		handler:    h.handler.WithGroup(name),
		hasTraceID: h.hasTraceID,
		hasSpanID:  h.hasSpanID,
	}
}

func traceKeys(attr slog.Attr) (hasTraceID, hasSpanID bool) {
	attr.Value = attr.Value.Resolve()
	if attr.Key == traceIDKey {
		hasTraceID = true
	}
	if attr.Key == spanIDKey {
		hasSpanID = true
	}
	if attr.Key != "" || attr.Value.Kind() != slog.KindGroup {
		return hasTraceID, hasSpanID
	}
	for _, child := range attr.Value.Group() {
		childTraceID, childSpanID := traceKeys(child)
		hasTraceID = hasTraceID || childTraceID
		hasSpanID = hasSpanID || childSpanID
	}
	return hasTraceID, hasSpanID
}
