package admin

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	pklogging "github.com/grpc-kit/pkg/logging"
)

func TestNewUsesFallbackLogger(t *testing.T) {
	api := New()

	if api.logger != pklogging.Fallback() {
		t.Fatal("New did not use logging.Fallback")
	}
	if api.config.logger != api.logger {
		t.Fatal("config and API loggers differ")
	}
}

func TestWithLogger(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))

	api := New(WithLogger(logger))

	if api.logger != logger {
		t.Fatal("WithLogger did not retain the supplied logger")
	}
	logWarnf(t.Context(), api.logger, "admin operation failed: %v", errors.New("boom"))
	if count := strings.Count(output.String(), "\n"); count != 1 {
		t.Fatalf("native log line count = %d, want 1; output = %q", count, output.String())
	}
	if !strings.Contains(output.String(), `"msg":"admin operation failed: boom"`) {
		t.Fatalf("formatted message was not preserved: %q", output.String())
	}
}

func TestWithLoggerNilUsesFallback(t *testing.T) {
	api := New(WithLogger(nil))

	if api.logger != pklogging.Fallback() {
		t.Fatal("nil slog logger did not use logging.Fallback")
	}
}

func TestGlobalSettingParseFallbackLogDoesNotExposeValueOrError(t *testing.T) {
	const invalidValue = "invalid-bool-setting-sensitive"
	original := globalSettingRegistry[globalSettingsCategorySecurity][globalSettingKeyLoginEnforceMFA]
	modified := original
	modified.DefaultValue = invalidValue
	globalSettingRegistry[globalSettingsCategorySecurity][globalSettingKeyLoginEnforceMFA] = modified
	t.Cleanup(func() {
		globalSettingRegistry[globalSettingsCategorySecurity][globalSettingKeyLoginEnforceMFA] = original
	})

	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})

	value, found, err := newGlobalSettingsReader(logger, nil).GetBool(
		t.Context(),
		globalSettingsCategorySecurity,
		globalSettingKeyLoginEnforceMFA,
	)
	if err != nil {
		t.Fatalf("GetBool() error = %v", err)
	}
	if value || found {
		t.Fatalf("GetBool() = (%v, %v), want built-in false fallback", value, found)
	}

	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("parse fallback warning count = %d, want 1; output=%q", got, output.String())
	}
	if !strings.Contains(output.String(), `"msg":"global setting parsing failed; using built-in fallback"`) {
		t.Fatalf("parse fallback warning output = %q", output.String())
	}
	for _, forbidden := range []string{invalidValue, "invalid syntax", `"event"`, `"setting_key"`} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("sensitive value %q leaked into parse fallback log: %q", forbidden, output.String())
		}
	}
}

func TestGlobalSettingReadFallbackLogDoesNotExposeError(t *testing.T) {
	const sensitiveType = globalSettingValueType("credential-type-sensitive")
	original := globalSettingRegistry[globalSettingsCategorySecurity][globalSettingKeyLoginAccessTokenTTL]
	modified := original
	modified.ValueType = sensitiveType
	globalSettingRegistry[globalSettingsCategorySecurity][globalSettingKeyLoginAccessTokenTTL] = modified
	t.Cleanup(func() {
		globalSettingRegistry[globalSettingsCategorySecurity][globalSettingKeyLoginAccessTokenTTL] = original
	})

	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})

	if got := loginAccessTokenTTLFrom(t.Context(), logger, nil); got != 24*time.Hour {
		t.Fatalf("loginAccessTokenTTLFrom() = %v, want 24h fallback", got)
	}

	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("read fallback warning count = %d, want 1; output=%q", got, output.String())
	}
	if !strings.Contains(output.String(), `"msg":"global setting read failed; using fallback"`) {
		t.Fatalf("read fallback warning output = %q", output.String())
	}
	for _, forbidden := range []string{string(sensitiveType), "type mismatch", `"event"`, `"setting_key"`} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("sensitive value %q leaked into read fallback log: %q", forbidden, output.String())
		}
	}
}
