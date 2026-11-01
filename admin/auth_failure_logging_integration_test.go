package admin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Failure-event formatting is independent of database dialect; provisioning
// still exercises both backends in TestExternalIdentityProvisioningIntegration.
func TestAuthenticationFailureLoggingIntegration(t *testing.T) {
	db := adminIntegrationClient(t)
	createTestLoginSigningKey(t, db)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"` + authFailureSensitiveValue + `"}`))
	}))
	t.Cleanup(server.Close)
	provider := createTestAuthProvider(t, db, "auth-log-oauth", adminv1.AuthProvider_OAUTH2)
	config, err := json.Marshal(oauthConfigData{ClientID: "test-client", AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token"})
	if err != nil {
		t.Fatal(err)
	}
	provider.Update().SetConfig(config).SetProviderStatus(int(adminv1.AuthProvider_ACTIVE)).SaveX(t.Context())
	bad := createTestAuthProvider(t, db, "auth-log-bad-secret", adminv1.AuthProvider_OAUTH2)
	bad.Update().SetSecretEncrypted([]byte(authFailureSensitiveValue)).SaveX(t.Context())
	ldap := createTestAuthProvider(t, db, "auth-log-ldap", adminv1.AuthProvider_LDAP)
	badLDAP := createTestAuthProvider(t, db, "auth-log-ldap-init", adminv1.AuthProvider_LDAP)
	badLDAP.Update().SetSecretEncrypted([]byte(authFailureSensitiveValue)).SaveX(t.Context())

	for _, tc := range []struct {
		name, provider, stage, reason, level string
		password                             bool
	}{
		{"invalid encrypted secret", bad.Code, "callback_provider_init", "internal_error", "ERROR", false},
		{"token exchange", provider.Code, "callback_exchange", "oauth_token_error", "ERROR", false},
		{"password check", ldap.Code, "password_check", "internal_error", "ERROR", true},
		{"password provider init", badLDAP.Code, "password_provider_init", "internal_error", "ERROR", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			api := New(WithLionClient(db), WithAESKey([]byte(adminTestAESKey)), WithOIDCProvider("", "test-client", ""),
				WithLogger(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))))
			var err error
			if tc.password {
				var response *adminv1.AuthToken
				response, err = api.CreateAuthLogin(t.Context(), &adminv1.CreateAuthLoginRequest{ProviderCode: tc.provider, Username: authFailureSensitiveValue,
					PasswordHash: base64.StdEncoding.EncodeToString([]byte(authFailureSensitiveValue))})
				if response != nil {
					t.Fatal("failed password login returned a token response")
				}
				if tc.stage == "password_provider_init" && status.Convert(err).Message() != "authentication failed" {
					t.Fatalf("password initialization public message changed: %v", err)
				}
			} else {
				var response *adminv1.GetAuthCallbackResponse
				response, err = api.GetAuthCallback(t.Context(), &adminv1.GetAuthCallbackRequest{ProviderName: tc.provider, Code: authFailureSensitiveValue})
				if response != nil {
					t.Fatal("failed callback returned a token response")
				}
				if status.Convert(err).Message() != "external authentication failed" {
					t.Fatalf("callback public message changed: %v", err)
				}
			}
			if status.Code(err) != codes.Unauthenticated || strings.Contains(err.Error(), authFailureSensitiveValue) || strings.Contains(err.Error(), server.URL) {
				t.Fatalf("unsafe or unexpected public error: %v", err)
			}
			assertAuthenticationFailureLog(t, output.String(), tc.provider, tc.stage, tc.reason, tc.level)
		})
	}
}
