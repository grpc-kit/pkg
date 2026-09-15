package admin

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
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
	api.logger.WarnContext(t.Context(), "admin operation failed")
	if count := strings.Count(output.String(), "\n"); count != 1 {
		t.Fatalf("native log line count = %d, want 1; output = %q", count, output.String())
	}
	if !strings.Contains(output.String(), `"msg":"admin operation failed"`) {
		t.Fatalf("log message was not preserved: %q", output.String())
	}
}

func TestLDAPLoginConfigurationLogIsStructuredAndDoesNotExposeCredentials(t *testing.T) {
	const (
		provider = "provider-sensitive"
		username = "username-sensitive"
		password = "password-sensitive"
	)

	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})
	social := &socialUsers{logger: logger, ProviderName: provider}

	if _, err := social.PasswordCheckLDAP(t.Context(), username, password); err == nil {
		t.Fatal("PasswordCheckLDAP() error = nil, want uninitialized configuration error")
	}

	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("LDAP error count = %d, want 1; output=%q", got, output.String())
	}
	if !strings.Contains(output.String(), `"msg":"LDAP login configuration is unavailable"`) {
		t.Fatalf("LDAP error output = %q", output.String())
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode LDAP error output: %v", err)
	}
	for key, want := range map[string]string{
		"event":    "ldap_login_configuration_unavailable",
		"provider": provider,
	} {
		if got := record[key]; got != want {
			t.Errorf("record[%q] = %v, want %q", key, got, want)
		}
	}
	for _, forbidden := range []string{username, password, `"error":`, `"username":`, `"password":`} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("sensitive value %q leaked into LDAP error: %q", forbidden, output.String())
		}
	}
}

func TestLDAPLoginEmptyCredentialsUseStructuredRejectionLog(t *testing.T) {
	const provider = "ldap-provider"
	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})
	social := &socialUsers{logger: logger, ProviderName: provider}

	result, err := social.PasswordCheckLDAP(t.Context(), "", "")
	if err != nil {
		t.Fatalf("PasswordCheckLDAP() error = %v", err)
	}
	if result == nil || result.OK {
		t.Fatalf("PasswordCheckLDAP() result = %+v, want unsuccessful result", result)
	}
	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("LDAP rejection count = %d, want 1; output=%q", got, output.String())
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode LDAP rejection output: %v", err)
	}
	for key, want := range map[string]string{
		"event":    "ldap_login_rejected",
		"provider": provider,
		"reason":   "missing_credentials",
	} {
		if got := record[key]; got != want {
			t.Errorf("record[%q] = %v, want %q", key, got, want)
		}
	}
	for _, key := range []string{"username_present", "password_present"} {
		if got := record[key]; got != false {
			t.Errorf("record[%q] = %v, want false", key, got)
		}
	}
	for _, forbidden := range []string{`"username":`, `"password":`, `"error":`} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("sensitive field %q leaked into LDAP rejection: %q", forbidden, output.String())
		}
	}
}

func TestLDAPInvalidPhoneLogIsStructuredAndDoesNotExposeValue(t *testing.T) {
	const (
		provider   = "ldap-provider"
		phoneValue = "phone-sensitive"
	)
	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})
	social := &socialUsers{
		logger:       logger,
		ProviderName: provider,
		ldapCfg:      &ldapConfigData{PhoneNumberDefaultRegion: "US"},
	}

	if got := social.normalizeLDAPUserPhone(t.Context(), &ldapUserAttrs{PhoneNumber: phoneValue}); got != nil {
		t.Fatalf("normalizeLDAPUserPhone() = %+v, want nil", got)
	}

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode LDAP phone output: %v", err)
	}
	for key, want := range map[string]string{
		"event":    "ldap_phone_ignored",
		"provider": provider,
		"reason":   "invalid_value",
	} {
		if got := record[key]; got != want {
			t.Errorf("record[%q] = %v, want %q", key, got, want)
		}
	}
	for _, forbidden := range []string{phoneValue, `"phone":`, `"error":`} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("sensitive value %q leaked into LDAP phone log: %q", forbidden, output.String())
		}
	}
}

func TestLDAPSearchConfigurationLogDoesNotExposeUsername(t *testing.T) {
	const (
		provider = "ldap-provider"
		username = "username-sensitive"
	)
	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})
	social := &socialUsers{logger: logger, ProviderName: provider, ldapCfg: &ldapConfigData{}}

	if _, err := social.findLDAPUser(t.Context(), nil, username); err == nil {
		t.Fatal("findLDAPUser() error = nil, want missing search base error")
	}

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("decode LDAP search output: %v", err)
	}
	for key, want := range map[string]string{
		"event":    "ldap_user_search_configuration_unavailable",
		"provider": provider,
	} {
		if got := record[key]; got != want {
			t.Errorf("record[%q] = %v, want %q", key, got, want)
		}
	}
	for _, forbidden := range []string{username, `"username":`, `"error":`} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("sensitive value %q leaked into LDAP search log: %q", forbidden, output.String())
		}
	}
}

func TestWithLoggerNilUsesFallback(t *testing.T) {
	api := New(WithLogger(nil))

	if api.logger != pklogging.Fallback() {
		t.Fatal("nil slog logger did not use logging.Fallback")
	}
}

func TestOIDCDiscoveryLogDoesNotExposeIssuerOrError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"issuer":`))
	}))
	t.Cleanup(server.Close)

	const issuerPath = "/issuer-sensitive"
	var output bytes.Buffer
	logger := pklogging.New(&output, pklogging.FormatJSON, &slog.HandlerOptions{Level: slog.LevelDebug})
	api := New(WithLogger(logger))

	api.enrichOAuthEndpoints(t.Context(), &adminv1.OAuthConfig{Issuer: server.URL + issuerPath})

	if got := strings.Count(output.String(), "\n"); got != 1 {
		t.Fatalf("OIDC warning count = %d, want 1; output=%q", got, output.String())
	}
	if !strings.Contains(output.String(), `"msg":"OIDC discovery failed"`) {
		t.Fatalf("OIDC warning output = %q", output.String())
	}
	for _, forbidden := range []string{server.URL, issuerPath, "unexpected end of JSON input", `"error"`, `"event"`} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("sensitive value %q leaked into OIDC warning: %q", forbidden, output.String())
		}
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
