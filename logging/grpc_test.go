package logging

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"testing"

	grpclogging "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
)

func TestGRPCLogger(t *testing.T) {
	var output bytes.Buffer
	logger := New(&output, FormatJSON, nil)
	adapter := NewGRPCLogger(logger)

	adapter.Log(t.Context(), grpclogging.LevelWarn, "finished call", "grpc.method", "Get", "attempt", 2, "odd")

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode log output: %v", err)
	}
	if got := record[slog.LevelKey]; got != "warn" {
		t.Errorf("level = %v, want warn", got)
	}
	if got := record["grpc.method"]; got != "Get" {
		t.Errorf("grpc.method = %v, want Get", got)
	}
	if got := record["attempt"]; got != float64(2) {
		t.Errorf("attempt = %v, want 2", got)
	}
	if got := record["odd"]; got != "" {
		t.Errorf("odd = %v, want empty string", got)
	}
}

func TestGRPCLoggerRejectsNonStringKey(t *testing.T) {
	adapter := NewGRPCLogger(New(io.Discard, FormatJSON, nil))
	defer func() {
		if recover() == nil {
			t.Fatal("Log did not panic for a non-string field key")
		}
	}()
	adapter.Log(t.Context(), grpclogging.LevelInfo, "message", 1, "value")
}

func TestGRPCLoggerAcceptsNilLogger(t *testing.T) {
	if adapter := NewGRPCLogger(nil); adapter == nil {
		t.Fatal("NewGRPCLogger(nil) returned nil")
	}
}
