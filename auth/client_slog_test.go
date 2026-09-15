package auth

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	pklogging "github.com/grpc-kit/pkg/logging"
	"google.golang.org/grpc/metadata"
)

func TestNewClientUsesFallbackLogger(t *testing.T) {
	client, err := NewClient(t.Context(), &Config{})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client.logger != pklogging.Fallback() {
		t.Fatal("NewClient did not use logging.Fallback")
	}
}

func TestWithLoggerOption(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	client := new(Client)

	got := client.WithLoggerOption(logger)

	if got != client {
		t.Fatal("WithLoggerOption did not return its receiver")
	}
	if client.logger != logger {
		t.Fatal("WithLoggerOption did not retain the supplied logger")
	}
	client.logger.Warn("native auth logger")
	if count := strings.Count(output.String(), "\n"); count != 1 {
		t.Fatalf("native log line count = %d, want 1; output = %q", count, output.String())
	}
}

func TestWithLoggerOptionNilUsesFallback(t *testing.T) {
	client := new(Client).WithLoggerOption(nil)

	if client.logger != pklogging.Fallback() {
		t.Fatal("nil slog logger did not use logging.Fallback")
	}
}

func TestOPADataProviderFailureLogDoesNotExposeError(t *testing.T) {
	const providerError = "postgres://user:password@policy-sensitive.example/provider"
	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})
	config := &Config{
		PackageName: "example.auth",
		OPARego: &OPARegoConfig{
			RegoBody: []byte("package example.auth\n\ndefault allow := true\n"),
			DataBody: []byte("action: ALLOW\npolicies: {}\n"),
			DataProviderFunc: func(context.Context) ([]byte, error) {
				return nil, errors.New(providerError)
			},
		},
	}
	client := &Client{
		logger:   logger,
		config:   config,
		envoy:    &envoyProxy{},
		rbacData: &rbacv3.RBAC{},
	}
	if err := client.initOPARego(t.Context()); err != nil {
		t.Fatalf("initOPARego() error = %v", err)
	}

	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("provider warning count = %d, want 1; output=%q", got, output.String())
	}
	if !strings.Contains(output.String(), `"level":"warn"`) ||
		!strings.Contains(output.String(), `"msg":"OPA dynamic data provider failed; using fallback data"`) {
		t.Fatalf("provider warning output = %q", output.String())
	}
	for _, forbidden := range []string{providerError, "user:password", `"event"`, `"error_kind"`} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("sensitive value %q leaked into provider log: %q", forbidden, output.String())
		}
	}
}

func TestOPAInputIsNotLogged(t *testing.T) {
	const (
		requestPath   = "/admin/tenant?token=query-secret&email=user%40sensitive.example"
		authorization = "Bearer authorization-secret"
		cookie        = "session=cookie-secret"
	)
	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})
	client := &Client{logger: logger, config: &Config{}, envoy: &envoyProxy{}}
	ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs(
		authMetadataPrefix+"request-uri", requestPath,
		authMetadataPrefix+"method", "POST",
		"authorization", authorization,
		"cookie", cookie,
	))
	allowed, err := client.Allow(ctx)
	if err != nil {
		t.Fatalf("Allow() error = %v", err)
	}
	if !allowed {
		t.Fatal("Allow() = false, want true without configured authorization backend")
	}

	if output.Len() != 0 {
		t.Fatalf("OPA input log output = %q, want empty", output.String())
	}
}
