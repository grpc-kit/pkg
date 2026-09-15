package cfg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pklogging "github.com/grpc-kit/pkg/logging"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"go.opentelemetry.io/otel/trace"
)

type objectStoreLogContextKey struct{}

type unsupportedObjectReader struct {
	io.Reader
}

type objectStoreRoundTripper func(*http.Request) (*http.Response, error)

func (f objectStoreRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestS3UploadSizeDetectionLogDoesNotExposeObjectKeyOrError(t *testing.T) {
	const objectKey = "tenant/credential/object-key-sensitive.txt"
	transportErr := errors.New("s3 endpoint response sensitive")
	client, err := minio.New("s3.example", &minio.Options{
		Creds:  credentials.NewStaticV4("test-access", "test-secret", ""),
		Secure: false,
		Transport: objectStoreRoundTripper(func(*http.Request) (*http.Response, error) {
			return nil, transportErr
		}),
	})
	if err != nil {
		t.Fatalf("minio.New() error = %v", err)
	}

	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 2, 3},
		SpanID:  trace.SpanID{4, 5, 6},
	})
	ctx := trace.ContextWithSpanContext(t.Context(), spanContext)
	ctx = context.WithValue(ctx, objectStoreLogContextKey{}, "context-object-secret")
	bucket := &S3Bucket{
		logger:   logger,
		name:     "test-bucket",
		client:   client,
		partSize: 5 * 1024 * 1024,
	}

	_, _ = bucket.Upload(ctx, objectKey, unsupportedObjectReader{Reader: strings.NewReader("payload")})

	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("JSON line count = %d, want 1; output=%q", got, output.String())
	}
	for _, forbidden := range []string{objectKey, "unsupportedObjectReader", transportErr.Error(), "context-object-secret"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("sensitive value %q leaked into object store log: %q", forbidden, output.String())
		}
	}

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode JSON log: %v", err)
	}
	for key, want := range map[string]string{
		"level":    "error",
		"msg":      "object store multipart size detection failed",
		"trace_id": spanContext.TraceID().String(),
		"span_id":  spanContext.SpanID().String(),
	} {
		if got := record[key]; got != want {
			t.Errorf("%s = %v, want %q", key, got, want)
		}
	}
	for _, key := range []string{"event", "error_kind"} {
		if _, exists := record[key]; exists {
			t.Errorf("unexpected structured field %q in object store log", key)
		}
	}
}

func TestS3InvalidCustomerKeyReturnsErrorWithoutDuplicateLog(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "customer-key-sensitive")
	if err := os.WriteFile(keyPath, []byte("too-short"), 0o600); err != nil {
		t.Fatalf("write test SSE-C key: %v", err)
	}

	var output bytes.Buffer
	config := &ObjstoreConfig{
		Type: "s3",
		Config: S3Config{
			Endpoint: "s3.example",
			Insecure: true,
			SSEConfig: SSEConfig{
				Type:          "SSE-C",
				EncryptionKey: keyPath,
			},
		},
	}
	_, err := config.BucketClient(pklogging.New(&output, pklogging.FormatJSON, nil))
	if err == nil || err.Error() != "initialize s3 client SSE-C" {
		t.Fatalf("BucketClient() error = %v, want stable SSE-C initialization error", err)
	}
	if output.Len() != 0 {
		t.Fatalf("duplicate SSE-C log output = %q, want empty", output.String())
	}
}
