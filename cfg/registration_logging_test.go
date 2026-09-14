package cfg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"syscall"
	"testing"

	pklogging "github.com/grpc-kit/pkg/logging"
	"go.opentelemetry.io/otel/trace"
)

type capturedRegistrationLog struct {
	contextValue any
	level        slog.Level
	message      string
	attrs        map[string]slog.Value
}

type registrationCaptureHandler struct {
	records *[]capturedRegistrationLog
}

func (h *registrationCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *registrationCaptureHandler) Handle(ctx context.Context, record slog.Record) error {
	attrs := make(map[string]slog.Value)
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value
		return true
	})
	*h.records = append(*h.records, capturedRegistrationLog{
		contextValue: ctx.Value(registrationContextKey{}),
		level:        record.Level,
		message:      record.Message,
		attrs:        attrs,
	})
	return nil
}

func (h *registrationCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *registrationCaptureHandler) WithGroup(string) slog.Handler      { return h }

type registrationContextKey struct{}

type registrationTimeoutError struct{}

func (registrationTimeoutError) Error() string { return "sensitive network timeout detail" }
func (registrationTimeoutError) Timeout() bool { return true }

func TestClassifyRegistrationError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", want: "none"},
		{name: "canceled", err: context.Canceled, want: "canceled"},
		{name: "deadline", err: context.DeadlineExceeded, want: "deadline_exceeded"},
		{name: "connection refused", err: syscall.ECONNREFUSED, want: "connection_refused"},
		{name: "timeout", err: registrationTimeoutError{}, want: "timeout"},
		{name: "other", err: errors.New("sensitive registry error detail"), want: "other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyRegistrationError(tt.err); got != tt.want {
				t.Errorf("classifyRegistrationError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRegistrationStructuredLogSchema(t *testing.T) {
	testErr := errors.New("registry unavailable")
	tests := []struct {
		name           string
		log            func(context.Context, *slog.Logger)
		wantLevel      slog.Level
		wantMessage    string
		wantEvent      string
		wantErrorKind  string
		wantRetryCount int
	}{
		{
			name:        "admin database unavailable",
			log:         logAdminDatabaseUnavailable,
			wantLevel:   slog.LevelInfo,
			wantMessage: "admin service database unavailable",
			wantEvent:   eventAdminDatabaseUnavailable,
		},
		{
			name: "health check failed",
			log: func(ctx context.Context, logger *slog.Logger) {
				logRegistryHealthCheckFailed(ctx, logger, testErr, 2, 5)
			},
			wantLevel:      slog.LevelError,
			wantMessage:    "service registry health check failed",
			wantEvent:      eventRegistryHealthCheckFailed,
			wantErrorKind:  "other",
			wantRetryCount: 2,
		},
		{
			name: "health check succeeded",
			log: func(ctx context.Context, logger *slog.Logger) {
				logRegistryHealthCheckSucceeded(ctx, logger, 2, 5)
			},
			wantLevel:      slog.LevelInfo,
			wantMessage:    "service registry health check succeeded",
			wantEvent:      eventRegistryHealthCheckSucceeded,
			wantRetryCount: 2,
		},
		{
			name: "health check retries exhausted",
			log: func(ctx context.Context, logger *slog.Logger) {
				logRegistryHealthCheckRetriesExhausted(ctx, logger, 5, 5)
			},
			wantLevel:      slog.LevelError,
			wantMessage:    "service registry health check retries exhausted",
			wantEvent:      eventRegistryHealthCheckRetriesExhausted,
			wantRetryCount: 5,
		},
		{
			name: "service registration failed",
			log: func(ctx context.Context, logger *slog.Logger) {
				logServiceRegistrationFailed(ctx, logger, testErr)
			},
			wantLevel:     slog.LevelError,
			wantMessage:   "service registration failed",
			wantEvent:     eventServiceRegistrationFailed,
			wantErrorKind: "other",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var records []capturedRegistrationLog
			logger := slog.New(&registrationCaptureHandler{records: &records})
			ctx := context.WithValue(t.Context(), registrationContextKey{}, tt.name)

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
			if record.message != tt.wantMessage {
				t.Errorf("message = %q, want %q", record.message, tt.wantMessage)
			}
			if got := record.attrs["event"].String(); got != tt.wantEvent {
				t.Errorf("event = %q, want %q", got, tt.wantEvent)
			}
			wantAttrCount := 1
			if tt.wantErrorKind != "" {
				wantAttrCount++
				if got := record.attrs["error_kind"].String(); got != tt.wantErrorKind {
					t.Errorf("error_kind = %q, want %q", got, tt.wantErrorKind)
				}
			}
			if tt.wantRetryCount != 0 {
				wantAttrCount += 2
				if got := record.attrs["retry_count"].Int64(); got != int64(tt.wantRetryCount) {
					t.Errorf("retry_count = %d, want %d", got, tt.wantRetryCount)
				}
				if got := record.attrs["retry_max"].Int64(); got != 5 {
					t.Errorf("retry_max = %d, want 5", got)
				}
			}
			if len(record.attrs) != wantAttrCount {
				t.Errorf("attr count = %d, want %d; attrs = %#v", len(record.attrs), wantAttrCount, record.attrs)
			}
		})
	}
}

func TestRegistrationStructuredLogJSONIncludesTraceWithoutSensitiveValues(t *testing.T) {
	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, nil)
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 2, 3},
		SpanID:  trace.SpanID{4, 5, 6},
	})
	ctx := trace.ContextWithSpanContext(t.Context(), spanContext)
	ctx = context.WithValue(ctx, registrationContextKey{}, "authorization-secret")

	publicAddress := "203.0.113.10:10081"
	networkError := &net.OpError{
		Op:   "dial",
		Net:  "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP("203.0.113.10"), Port: 10081},
		Err:  syscall.ECONNREFUSED,
	}
	logRegistryHealthCheckFailed(ctx, logger, networkError, 2, 5)

	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("JSON line count = %d, want 1; output=%q", got, output.String())
	}
	for _, forbidden := range []string{"authorization-secret", publicAddress, "public_address", networkError.Error()} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("sensitive or high-cardinality value %q leaked into log: %q", forbidden, output.String())
		}
	}

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode JSON log: %v", err)
	}
	for key, want := range map[string]string{
		"level":      "error",
		"msg":        "service registry health check failed",
		"event":      eventRegistryHealthCheckFailed,
		"error_kind": "connection_refused",
		"trace_id":   spanContext.TraceID().String(),
		"span_id":    spanContext.SpanID().String(),
	} {
		if got := record[key]; got != want {
			t.Errorf("%s = %v, want %q", key, got, want)
		}
	}
	if got := record["retry_count"]; got != float64(2) {
		t.Errorf("retry_count = %v, want 2", got)
	}
	if got := record["retry_max"]; got != float64(5) {
		t.Errorf("retry_max = %v, want 5", got)
	}
}
