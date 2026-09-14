package cfg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	pkgauth "github.com/grpc-kit/pkg/auth"
	pkgcrypto "github.com/grpc-kit/pkg/crypto"
	pklogging "github.com/grpc-kit/pkg/logging"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/metadata"
)

type capturedSecurityLog struct {
	contextValue any
	level        slog.Level
	message      string
	attrs        map[string]slog.Value
}

type securityCaptureHandler struct {
	records *[]capturedSecurityLog
}

func (h *securityCaptureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *securityCaptureHandler) Handle(ctx context.Context, record slog.Record) error {
	attrs := make(map[string]slog.Value)
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value
		return true
	})
	*h.records = append(*h.records, capturedSecurityLog{
		contextValue: ctx.Value(securityLogContextKey{}),
		level:        record.Level,
		message:      record.Message,
		attrs:        attrs,
	})
	return nil
}

func (h *securityCaptureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *securityCaptureHandler) WithGroup(string) slog.Handler      { return h }

type securityLogContextKey struct{}

type securityChannelHandler struct {
	records chan<- capturedSecurityLog
}

func (h *securityChannelHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *securityChannelHandler) Handle(ctx context.Context, record slog.Record) error {
	attrs := make(map[string]slog.Value)
	record.Attrs(func(attr slog.Attr) bool {
		attrs[attr.Key] = attr.Value
		return true
	})
	h.records <- capturedSecurityLog{
		contextValue: ctx.Value(securityLogContextKey{}),
		level:        record.Level,
		message:      record.Message,
		attrs:        attrs,
	}
	return nil
}

func (h *securityChannelHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *securityChannelHandler) WithGroup(string) slog.Handler      { return h }

func TestClassifySecurityError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "malformed", err: jwt.ErrTokenMalformed, want: "token_malformed"},
		{name: "signature", err: jwt.ErrTokenSignatureInvalid, want: "token_signature_invalid"},
		{name: "unverifiable", err: jwt.ErrTokenUnverifiable, want: "token_unverifiable"},
		{name: "expired", err: jwt.ErrTokenExpired, want: "token_expired"},
		{name: "not valid yet", err: jwt.ErrTokenNotValidYet, want: "token_not_valid_yet"},
		{name: "used before issued", err: jwt.ErrTokenUsedBeforeIssued, want: "token_used_before_issued"},
		{name: "missing claim", err: jwt.ErrTokenRequiredClaimMissing, want: "token_required_claim_missing"},
		{name: "audience", err: jwt.ErrTokenInvalidAudience, want: "token_invalid_audience"},
		{name: "issuer", err: jwt.ErrTokenInvalidIssuer, want: "token_invalid_issuer"},
		{name: "subject", err: jwt.ErrTokenInvalidSubject, want: "token_invalid_subject"},
		{name: "id", err: jwt.ErrTokenInvalidId, want: "token_invalid_id"},
		{name: "claims", err: jwt.ErrTokenInvalidClaims, want: "token_invalid_claims"},
		{name: "key", err: jwt.ErrInvalidKey, want: "token_invalid_key"},
		{name: "context", err: context.Canceled, want: "canceled"},
		{name: "other", err: errors.New("sensitive provider response"), want: "other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifySecurityError(tt.err); got != tt.want {
				t.Errorf("classifySecurityError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestInitSecurityLogsOIDCDiscoveryRetry(t *testing.T) {
	const issuerPath = "/issuer-sensitive"

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"issuer":`))
	}))
	t.Cleanup(server.Close)

	records := make(chan capturedSecurityLog, 2)
	logger := slog.New(&securityChannelHandler{records: records})
	c := &LocalConfig{
		logger: logger,
		Security: &SecurityConfig{
			Enable: true,
			Authentication: &Authentication{
				OIDCProvider: &OIDCProvider{Issuer: server.URL + issuerPath},
			},
		},
	}
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), securityLogContextKey{}, "oidc-discovery"))
	t.Cleanup(cancel)

	if err := c.initSecurity(ctx); err != nil {
		t.Fatalf("initSecurity() error = %v", err)
	}

	select {
	case record := <-records:
		if record.contextValue != "oidc-discovery" {
			t.Errorf("context value = %v, want %q", record.contextValue, "oidc-discovery")
		}
		if record.level != slog.LevelDebug {
			t.Errorf("level = %v, want %v", record.level, slog.LevelDebug)
		}
		if record.message != "OIDC provider discovery failed; retrying" {
			t.Errorf("message = %q", record.message)
		}
		if got := record.attrs["event"].String(); got != eventOIDCProviderDiscoveryRetry {
			t.Errorf("event = %q, want %q", got, eventOIDCProviderDiscoveryRetry)
		}
		if got := record.attrs["error_kind"].String(); got != "other" {
			t.Errorf("error_kind = %q, want other", got)
		}
		if len(record.attrs) != 2 {
			t.Errorf("attr count = %d, want 2; attrs = %#v", len(record.attrs), record.attrs)
		}
		if strings.Contains(record.message, issuerPath) {
			t.Errorf("issuer path leaked into message: %q", record.message)
		}
		for key, value := range record.attrs {
			if strings.Contains(value.String(), issuerPath) {
				t.Errorf("issuer path leaked into %s: %q", key, value.String())
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OIDC discovery retry log was not emitted")
	}
	cancel()

	select {
	case record := <-records:
		if record.level != slog.LevelError {
			t.Errorf("final level = %v, want %v", record.level, slog.LevelError)
		}
		if record.message != "OIDC verifier initialization stopped" {
			t.Errorf("final message = %q", record.message)
		}
		if got := record.attrs["event"].String(); got != eventOIDCVerifierInitializationFailed {
			t.Errorf("final event = %q, want %q", got, eventOIDCVerifierInitializationFailed)
		}
		if got := record.attrs["error_kind"].String(); got != "canceled" {
			t.Errorf("final error_kind = %q, want canceled", got)
		}
		if len(record.attrs) != 2 {
			t.Errorf("final attr count = %d, want 2; attrs = %#v", len(record.attrs), record.attrs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OIDC initialization failure log was not emitted")
	}
}

func TestInitSecurityLogsOIDCVerifierReady(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(map[string]string{
			"issuer":                 server.URL,
			"authorization_endpoint": server.URL + "/authorize",
			"token_endpoint":         server.URL + "/token",
			"jwks_uri":               server.URL + "/keys",
		})
	}))
	t.Cleanup(server.Close)

	records := make(chan capturedSecurityLog, 1)
	logger := slog.New(&securityChannelHandler{records: records})
	c := &LocalConfig{
		logger: logger,
		Security: &SecurityConfig{
			Enable: true,
			Authentication: &Authentication{
				OIDCProvider: &OIDCProvider{Issuer: server.URL},
			},
		},
	}
	ctx, cancel := context.WithCancel(context.WithValue(t.Context(), securityLogContextKey{}, "oidc-ready"))
	t.Cleanup(cancel)

	if err := c.initSecurity(ctx); err != nil {
		t.Fatalf("initSecurity() error = %v", err)
	}

	select {
	case record := <-records:
		if record.contextValue != "oidc-ready" {
			t.Errorf("context value = %v, want %q", record.contextValue, "oidc-ready")
		}
		if record.level != slog.LevelInfo {
			t.Errorf("level = %v, want %v", record.level, slog.LevelInfo)
		}
		if record.message != "OIDC verifier is ready" {
			t.Errorf("message = %q", record.message)
		}
		if got := record.attrs["event"].String(); got != eventOIDCVerifierReady {
			t.Errorf("event = %q, want %q", got, eventOIDCVerifierReady)
		}
		if len(record.attrs) != 1 {
			t.Errorf("attr count = %d, want 1; attrs = %#v", len(record.attrs), record.attrs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OIDC verifier ready log was not emitted")
	}
}

func expiredBearerLoggingConfig(t *testing.T, logger *slog.Logger, subject, email string) (*LocalConfig, string) {
	t.Helper()

	const password = "bearer-signing-secret"
	claims := &pkgauth.AccessTokenClaims{CommonClaims: pkgauth.CommonClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
		Email: email,
	}}
	token, err := pkgauth.SignAccessTokenHMACKey(claims, []byte(pkgcrypto.SHA256([]byte(password))))
	if err != nil {
		t.Fatalf("sign expired access token: %v", err)
	}

	return &LocalConfig{
		logger: logger,
		Security: &SecurityConfig{
			Enable: true,
			Authentication: &Authentication{
				OIDCProvider: &OIDCProvider{
					Issuer: "https://issuer.example",
					Config: &OIDCConfig{
						SupportedSigningAlgs: []string{"HS256"},
						SkipIssuerCheck:      true,
						SkipClientIDCheck:    true,
					},
				},
				HTTPUsers: []*BasicAuth{{
					UserID:   pkgcrypto.Username2UserID(subject),
					Username: subject,
					Password: password,
				}},
			},
		},
	}, token
}

func runExpiredBearerValidation(t *testing.T, ctx context.Context, logger *slog.Logger, subject, email string) string {
	t.Helper()

	c, token := expiredBearerLoggingConfig(t, logger, subject, email)
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+token))
	if _, err := c.authValidate()(ctx); err == nil {
		t.Fatal("authValidate() error = nil, want unauthenticated")
	}
	return token
}

func TestAuthValidateLogsBearerVerificationFailure(t *testing.T) {
	var records []capturedSecurityLog
	logger := slog.New(&securityCaptureHandler{records: &records})
	ctx := context.WithValue(t.Context(), securityLogContextKey{}, "bearer-validation")

	runExpiredBearerValidation(t, ctx, logger, "subject-sensitive", "person-sensitive@example.com")

	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1; records = %#v", len(records), records)
	}
	record := records[0]
	if record.contextValue != "bearer-validation" {
		t.Errorf("context value = %v, want %q", record.contextValue, "bearer-validation")
	}
	if record.level != slog.LevelWarn {
		t.Errorf("level = %v, want %v", record.level, slog.LevelWarn)
	}
	if record.message != "bearer token verification failed" {
		t.Errorf("message = %q", record.message)
	}
	if got := record.attrs["event"].String(); got != eventBearerTokenVerificationFailed {
		t.Errorf("event = %q, want %q", got, eventBearerTokenVerificationFailed)
	}
	if got := record.attrs["error_kind"].String(); got != "token_expired" {
		t.Errorf("error_kind = %q, want token_expired", got)
	}
	if !record.attrs["subject_present"].Bool() || !record.attrs["email_present"].Bool() {
		t.Errorf("claim presence attrs = %#v, want both true", record.attrs)
	}
	if len(record.attrs) != 4 {
		t.Errorf("attr count = %d, want 4; attrs = %#v", len(record.attrs), record.attrs)
	}
}

func TestCheckPermissionLogsAllowListConflict(t *testing.T) {
	const method = "/grpc_kit.api.known.admin.v1.KnownAdmin/ListUsers"

	var records []capturedSecurityLog
	logger := slog.New(&securityCaptureHandler{records: &records})
	c := newCheckPermissionTestConfig()
	c.logger = logger
	c.Security.Authorization.AllowedGroups = []string{"legacy-admin"}
	c.Security.Authorization.AllowedRoles = []string{"admin"}
	ctx := context.WithValue(t.Context(), securityLogContextKey{}, "permission-check")

	err := c.checkPermission(ctx, method, []string{"admin"})
	isPermissionDenied(t, err)

	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1; records = %#v", len(records), records)
	}
	record := records[0]
	if record.contextValue != "permission-check" {
		t.Errorf("context value = %v, want %q", record.contextValue, "permission-check")
	}
	if record.level != slog.LevelError {
		t.Errorf("level = %v, want %v", record.level, slog.LevelError)
	}
	if record.message != "authorization role allow-lists conflict" {
		t.Errorf("message = %q", record.message)
	}
	if got := record.attrs["event"].String(); got != eventAuthorizationRoleAllowListsConflict {
		t.Errorf("event = %q, want %q", got, eventAuthorizationRoleAllowListsConflict)
	}
	if got := record.attrs["grpc.method"].String(); got != method {
		t.Errorf("grpc.method = %q, want %q", got, method)
	}
	if got := record.attrs["allowed_groups_count"].Int64(); got != 1 {
		t.Errorf("allowed_groups_count = %d, want 1", got)
	}
	if got := record.attrs["allowed_roles_count"].Int64(); got != 1 {
		t.Errorf("allowed_roles_count = %d, want 1", got)
	}
	if len(record.attrs) != 4 {
		t.Errorf("attr count = %d, want 4; attrs = %#v", len(record.attrs), record.attrs)
	}
}

func runOPAPolicyEvaluationFailure(t *testing.T, ctx context.Context, logger *slog.Logger, method, requestPath string) {
	t.Helper()

	authClient, err := pkgauth.NewClient(ctx, &pkgauth.Config{PackageName: "test.policy"})
	if err != nil {
		t.Fatalf("auth.NewClient() error = %v", err)
	}
	enabled := true
	disabled := false
	c := &LocalConfig{
		logger: logger,
		Security: &SecurityConfig{
			Enable:     true,
			authClient: authClient,
			Authorization: &Authorization{
				OPANative:      OPANative{Enabled: &enabled},
				OPAExternal:    OPAExternal{Enabled: &disabled},
				OPAEnvoyPlugin: OPAEnvoyPlugin{Enabled: &disabled},
			},
		},
	}
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("grpc-kit-request-uri", requestPath))
	if err := c.checkPermission(ctx, method, []string{"admin"}); err == nil {
		t.Fatal("checkPermission() error = nil, want PermissionDenied")
	}
}

func TestCheckPermissionLogsOPAPolicyEvaluationFailure(t *testing.T) {
	const method = "/grpc_kit.api.known.admin.v1.KnownAdmin/ListUsers"

	var records []capturedSecurityLog
	logger := slog.New(&securityCaptureHandler{records: &records})
	ctx := context.WithValue(t.Context(), securityLogContextKey{}, "opa-evaluation")
	runOPAPolicyEvaluationFailure(t, ctx, logger, method, "%invalid-path")

	if len(records) != 1 {
		t.Fatalf("record count = %d, want 1; records = %#v", len(records), records)
	}
	record := records[0]
	if record.contextValue != "opa-evaluation" {
		t.Errorf("context value = %v, want %q", record.contextValue, "opa-evaluation")
	}
	if record.level != slog.LevelError {
		t.Errorf("level = %v, want %v", record.level, slog.LevelError)
	}
	if record.message != "OPA policy evaluation failed" {
		t.Errorf("message = %q", record.message)
	}
	if got := record.attrs["event"].String(); got != eventOPAPolicyEvaluationFailed {
		t.Errorf("event = %q, want %q", got, eventOPAPolicyEvaluationFailed)
	}
	if got := record.attrs["grpc.method"].String(); got != method {
		t.Errorf("grpc.method = %q, want %q", got, method)
	}
	if got := record.attrs["error_kind"].String(); got != "other" {
		t.Errorf("error_kind = %q, want other", got)
	}
	if len(record.attrs) != 3 {
		t.Errorf("attr count = %d, want 3; attrs = %#v", len(record.attrs), record.attrs)
	}
}

func TestSecurityStructuredLogsDoNotExposeSensitiveValues(t *testing.T) {
	const (
		subject = "subject-sensitive"
		email   = "person-sensitive@example.com"
		body    = "%opa-secret"
	)

	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})
	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: trace.TraceID{1, 2, 3},
		SpanID:  trace.SpanID{4, 5, 6},
	})
	ctx := trace.ContextWithSpanContext(t.Context(), spanContext)
	ctx = context.WithValue(ctx, securityLogContextKey{}, "context-authorization-secret")

	token := runExpiredBearerValidation(t, ctx, logger, subject, email)
	runOPAPolicyEvaluationFailure(t, ctx, logger,
		"/grpc_kit.api.known.admin.v1.KnownAdmin/ListUsers", body)

	if got := strings.Count(output.String(), "\n"); got != 2 {
		t.Fatalf("JSON line count = %d, want 2; output=%q", got, output.String())
	}
	for _, forbidden := range []string{token, subject, email, body, "context-authorization-secret"} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("sensitive value %q leaked into log: %q", forbidden, output.String())
		}
	}

	for lineNumber, line := range bytes.Split(bytes.TrimSpace(output.Bytes()), []byte("\n")) {
		var record map[string]any
		if err := json.Unmarshal(line, &record); err != nil {
			t.Fatalf("decode JSON log line %d: %v", lineNumber, err)
		}
		if got := record["trace_id"]; got != spanContext.TraceID().String() {
			t.Errorf("line %d trace_id = %v, want %q", lineNumber, got, spanContext.TraceID())
		}
		if got := record["span_id"]; got != spanContext.SpanID().String() {
			t.Errorf("line %d span_id = %v, want %q", lineNumber, got, spanContext.SpanID())
		}
	}
}
