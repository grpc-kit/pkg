package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/lib/pq"
	"golang.org/x/oauth2"
)

const authFailureSensitiveValue = "test-only-sensitive-marker"

type opaqueAuthFailure struct{}

func (opaqueAuthFailure) Error() string { panic("must not format authentication errors") }

func assertAuthenticationFailureLog(t *testing.T, output, provider, stage, reason, level string) {
	t.Helper()
	var failure map[string]any
	count := 0
	for line := range strings.SplitSeq(strings.TrimSpace(output), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("decode log record: %v", err)
		}
		if record["event"] == "authentication_failed" {
			failure = record
			count++
		}
	}
	if count != 1 {
		t.Fatalf("authentication failure event count = %d, want 1; output=%s", count, output)
	}
	for key, want := range map[string]string{"provider": provider, "stage": stage, "reason": reason, "level": level} {
		if failure[key] != want {
			t.Errorf("log[%s] = %v, want %s", key, failure[key], want)
		}
	}
	for _, forbidden := range []string{authFailureSensitiveValue, `"error":`, `"code":`, `"password":`, `"token":`, `"body":`, `"username":`} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("sensitive value/field %q leaked into logs: %s", forbidden, output)
		}
	}
	if errorType, ok := failure["error_type"].(string); !ok || errorType == "" {
		t.Fatal("missing error type")
	}
}

func TestAuthenticationFailureLogsClassifyWithoutFormattingErrors(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		reason string
		level  string
	}{
		{"opaque", opaqueAuthFailure{}, "internal_error", "ERROR"},
		{"canceled", context.Canceled, "canceled", "WARN"},
		{"username", errExternalUsernameConflict, "username_unavailable", "WARN"},
		{"postgres", &pq.Error{Code: "23505", Message: authFailureSensitiveValue, Detail: authFailureSensitiveValue}, "database_error", "ERROR"},
		{"mysql", &mysqlDriver.MySQLError{Number: 1062, Message: authFailureSensitiveValue}, "database_error", "ERROR"},
		{"oauth", &oauth2.RetrieveError{Response: &http.Response{StatusCode: http.StatusBadRequest}, Body: []byte(authFailureSensitiveValue), ErrorCode: authFailureSensitiveValue, ErrorDescription: authFailureSensitiveValue}, "oauth_token_error", "ERROR"},
		{"network", &url.Error{Op: "Post", URL: "https://example.invalid/?code=" + authFailureSensitiveValue, Err: &net.DNSError{Err: authFailureSensitiveValue, Name: authFailureSensitiveValue}}, "network_error", "ERROR"},
		{"json", &json.UnmarshalTypeError{Value: authFailureSensitiveValue, Type: reflect.TypeFor[string](), Field: authFailureSensitiveValue}, "invalid_json", "ERROR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			// A standard slog handler performs no application-specific redaction.
			api := New(WithLogger(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))))
			err := tc.err
			if tc.name != "opaque" {
				err = fmt.Errorf("%s: %w", authFailureSensitiveValue, err)
			}
			api.logAuthenticationFailure(t.Context(), "test-provider", "callback_exchange", err)
			assertAuthenticationFailureLog(t, output.String(), "test-provider", "callback_exchange", tc.reason, tc.level)
		})
	}
}
