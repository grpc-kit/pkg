package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	cloudevent "github.com/cloudevents/sdk-go/v2/event"
	"github.com/cloudevents/sdk-go/v2/protocol"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"

	pklogging "github.com/grpc-kit/pkg/logging"
)

type capturedAuditLog struct {
	contextValue any
	level        slog.Level
	message      string
	attrs        map[string]slog.Value
}

type auditCaptureHandler struct {
	records *[]capturedAuditLog
}

func (h *auditCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *auditCaptureHandler) Handle(ctx context.Context, record slog.Record) error {
	attrs := make(map[string]slog.Value)
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value
		return true
	})
	*h.records = append(*h.records, capturedAuditLog{
		contextValue: ctx.Value(auditContextKey{}),
		level:        record.Level,
		message:      record.Message,
		attrs:        attrs,
	})
	return nil
}

func (h *auditCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *auditCaptureHandler) WithGroup(string) slog.Handler      { return h }

type auditContextKey struct{}

func TestStructuredAuditLogSchema(t *testing.T) {
	testErr := errors.New("audit failure")
	tests := []struct {
		name       string
		log        func(context.Context, *slog.Logger)
		wantLevel  slog.Level
		wantMsg    string
		wantEvent  string
		wantMethod string
	}{
		{
			name: "delivery warning",
			log: func(ctx context.Context, logger *slog.Logger) {
				logAuditEventDeliveryFailed(ctx, logger, "ListUsers", testErr)
			},
			wantLevel:  slog.LevelWarn,
			wantMsg:    "failed to send audit event",
			wantEvent:  auditEventDeliveryFailed,
			wantMethod: "ListUsers",
		},
		{
			name: "delivery error",
			log: func(ctx context.Context, logger *slog.Logger) {
				logAuditEventDeliveryError(ctx, logger, "ListUsers", testErr)
			},
			wantLevel:  slog.LevelError,
			wantMsg:    "failed to send audit event",
			wantEvent:  auditEventDeliveryFailed,
			wantMethod: "ListUsers",
		},
		{
			name: "encoding warning",
			log: func(ctx context.Context, logger *slog.Logger) {
				logAuditEventEncodingFailed(ctx, logger, "ListUsers", testErr)
			},
			wantLevel:  slog.LevelWarn,
			wantMsg:    "failed to encode audit event",
			wantEvent:  auditEventEncodingFailed,
			wantMethod: "ListUsers",
		},
		{
			name: "encoding error",
			log: func(ctx context.Context, logger *slog.Logger) {
				logAuditEventEncodingError(ctx, logger, "ListUsers", testErr)
			},
			wantLevel:  slog.LevelError,
			wantMsg:    "failed to encode audit event",
			wantEvent:  auditEventEncodingFailed,
			wantMethod: "ListUsers",
		},
		{
			name: "method parse warning",
			log: func(ctx context.Context, logger *slog.Logger) {
				logAuditGRPCMethodParseFailed(ctx, logger, "/invalid", testErr)
			},
			wantLevel:  slog.LevelWarn,
			wantMsg:    "failed to parse gRPC method",
			wantEvent:  auditGRPCMethodParseFailed,
			wantMethod: "/invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var records []capturedAuditLog
			logger := slog.New(&auditCaptureHandler{records: &records})
			ctx := context.WithValue(t.Context(), auditContextKey{}, tt.name)

			tt.log(ctx, logger)

			if len(records) != 1 {
				t.Fatalf("record count = %d, want 1", len(records))
			}
			record := records[0]
			if record.contextValue != tt.name {
				t.Errorf("context value = %v, want %q", record.contextValue, tt.name)
			}
			if record.level != tt.wantLevel {
				t.Errorf("level = %v, want %v", record.level, tt.wantLevel)
			}
			if record.message != tt.wantMsg {
				t.Errorf("message = %q, want %q", record.message, tt.wantMsg)
			}
			if got := record.attrs["event"].String(); got != tt.wantEvent {
				t.Errorf("event = %q, want %q", got, tt.wantEvent)
			}
			if got := record.attrs["grpc.method"].String(); got != tt.wantMethod {
				t.Errorf("grpc.method = %q, want %q", got, tt.wantMethod)
			}
			if got, ok := record.attrs["error"].Any().(error); !ok || !errors.Is(got, testErr) {
				t.Errorf("error attr = %#v, want typed test error", record.attrs["error"].Any())
			}
		})
	}
}

func TestStructuredAuditLogJSONIncludesTraceWithoutContextValues(t *testing.T) {
	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, nil)
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 2, 3},
		SpanID:  trace.SpanID{4, 5, 6},
	})
	ctx := trace.ContextWithSpanContext(t.Context(), spanContext)
	ctx = context.WithValue(ctx, auditContextKey{}, "authorization-secret")

	logAuditEventDeliveryFailed(ctx, logger, "ListUsers", errors.New("delivery failed"))

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
		"level":       "warn",
		"msg":         "failed to send audit event",
		"event":       auditEventDeliveryFailed,
		"grpc.method": "ListUsers",
		"error":       "delivery failed",
		"trace_id":    spanContext.TraceID().String(),
		"span_id":     spanContext.SpanID().String(),
	} {
		if got := record[key]; got != want {
			t.Errorf("%s = %v, want %q", key, got, want)
		}
	}
}

func TestInterceptorsStructureGRPCMethodParseFailures(t *testing.T) {
	tests := []struct {
		name string
		run  func(*slog.Logger, context.Context) error
	}{
		{
			name: "unary",
			run: func(logger *slog.Logger, ctx context.Context) error {
				interceptor := UnaryServerInterceptor(WithLogger(logger))
				_, err := interceptor(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/invalid"}, func(context.Context, any) (any, error) {
					return nil, nil
				})
				return err
			},
		},
		{
			name: "stream",
			run: func(logger *slog.Logger, ctx context.Context) error {
				interceptor := StreamServerInterceptor(WithLogger(logger))
				stream := &auditTestServerStream{ServerStream: nil, ctx: ctx}
				return interceptor(nil, stream, &grpc.StreamServerInfo{FullMethod: "/invalid"}, func(any, grpc.ServerStream) error {
					return nil
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalLogger := defaultOption.logger
			defer func() {
				defaultOption.logger = originalLogger
			}()

			var records []capturedAuditLog
			logger := slog.New(&auditCaptureHandler{records: &records})
			ctx := context.WithValue(t.Context(), auditContextKey{}, tt.name)

			if err := tt.run(logger, ctx); err != nil {
				t.Fatalf("interceptor returned error: %v", err)
			}
			if len(records) != 1 {
				t.Fatalf("record count = %d, want 1", len(records))
			}
			record := records[0]
			if record.contextValue != tt.name {
				t.Errorf("context value = %v, want %q", record.contextValue, tt.name)
			}
			if record.message != "failed to parse gRPC method" {
				t.Errorf("message = %q", record.message)
			}
			if got := record.attrs["event"].String(); got != auditGRPCMethodParseFailed {
				t.Errorf("event = %q", got)
			}
			if got := record.attrs["grpc.method"].String(); got != "/invalid" {
				t.Errorf("grpc.method = %q", got)
			}
			if _, ok := record.attrs["error"].Any().(error); !ok {
				t.Errorf("error attr = %#v, want typed error", record.attrs["error"].Any())
			}
		})
	}
}

type auditTestServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *auditTestServerStream) Context() context.Context { return s.ctx }

type auditTestClient struct {
	result protocol.Result
}

func (c *auditTestClient) Send(context.Context, cloudevent.Event) protocol.Result {
	return c.result
}

func (*auditTestClient) Request(context.Context, cloudevent.Event) (*cloudevent.Event, protocol.Result) {
	return nil, nil
}

func (*auditTestClient) StartReceiver(context.Context, any) error { return nil }

func TestSendEventStructuresSynchronousDeliveryFailure(t *testing.T) {
	var records []capturedAuditLog
	testErr := errors.New("delivery failed")
	mustSucceed := true
	eventData := &EventData{
		opt: &interceptorOption{
			logger:      slog.New(&auditCaptureHandler{records: &records}),
			client:      &auditTestClient{result: testErr},
			mustSucceed: &mustSucceed,
		},
		GRPCMethod: "ListUsers",
	}

	if err := eventData.sendEvent(t.Context()); err == nil {
		t.Fatal("sendEvent error = nil, want delivery failure")
	}
	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1", len(records))
	}
	record := records[0]
	if record.level != slog.LevelError || record.message != "failed to send audit event" {
		t.Errorf("record = level %v message %q", record.level, record.message)
	}
	if got := record.attrs["event"].String(); got != auditEventDeliveryFailed {
		t.Errorf("event = %q", got)
	}
	if got := record.attrs["grpc.method"].String(); got != "ListUsers" {
		t.Errorf("grpc.method = %q", got)
	}
	if got, ok := record.attrs["error"].Any().(error); !ok || !errors.Is(got, testErr) {
		t.Errorf("error attr = %#v, want typed delivery error", record.attrs["error"].Any())
	}
}
