package admin

import (
	"context"
	"strings"
	"testing"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"google.golang.org/protobuf/encoding/protojson"
)

func testUserAuthIdentity(
	id int,
	userID int,
	provider *lion.AuthProviders,
	providerUserID string,
) *lion.UserIdentities {
	return &lion.UserIdentities{
		ID:             id,
		UserID:         userID,
		ProviderID:     provider.ID,
		ProviderUserID: providerUserID,
		Edges:          lion.UserIdentitiesEdges{LionAuthProviders: provider},
	}
}

func TestListUserAuthBindingsRejectsInvalidRequestBeforeDatabaseAccess(t *testing.T) {
	a := &KnownAdminAPI{}
	for _, req := range []*adminv1.ListUserAuthBindingsRequest{nil, {}, {UserId: -1}} {
		_, err := a.ListUserAuthBindings(context.Background(), req)
		if err == nil || errs.FromError(err).HTTPStatusCode() != 400 {
			t.Fatalf("ListUserAuthBindings(%v) error = %v, want HTTP 400", req, err)
		}
	}
}

func TestProjectUserAuthBindingsProjectsAndSortsMultipleProviders(t *testing.T) {
	createdAt := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	updatedAt := time.Date(2026, time.August, 20, 1, 15, 0, 0, time.UTC)

	localProvider := &lion.AuthProviders{
		ID:             1,
		Code:           "local",
		DisplayName:    "Local password",
		ProviderType:   int(adminv1.AuthProvider_LOCAL),
		ProviderStatus: int(adminv1.AuthProvider_ACTIVE),
		SortOrder:      10,
	}
	ldapProvider := &lion.AuthProviders{
		ID:             4,
		Code:           "corp-ldap",
		DisplayName:    "Corporate LDAP",
		ProviderType:   int(adminv1.AuthProvider_LDAP),
		ProviderStatus: int(adminv1.AuthProvider_PENDING),
		SortOrder:      10,
	}
	oidcProvider := &lion.AuthProviders{
		ID:             7,
		Code:           "corp-oidc",
		DisplayName:    "Corporate OIDC",
		ProviderType:   int(adminv1.AuthProvider_OIDC),
		ProviderStatus: int(adminv1.AuthProvider_DISABLED),
		SortOrder:      20,
		IconURL:        "https://cdn.example.test/oidc.svg",
	}

	local := testUserAuthIdentity(30, 1001, localProvider, "local-user-1001")
	local.PasswordHash = "test-bcrypt-hash"
	local.CreatedAt = createdAt
	local.UpdatedAt = updatedAt

	ldap := testUserAuthIdentity(20, 1001, ldapProvider, "uid=alice,ou=people,dc=example,dc=test")
	oidc := testUserAuthIdentity(10, 1001, oidcProvider, "oidc-subject-8f31")
	oidc.ProviderUnionID = "directory-person-52"

	bindings, err := projectUserAuthBindings(context.Background(), []*lion.UserIdentities{oidc, ldap, local})
	if err != nil {
		t.Fatalf("projectUserAuthBindings: %v", err)
	}
	if len(bindings) != 3 {
		t.Fatalf("len(bindings) = %d, want 3", len(bindings))
	}
	if bindings[0].GetId() != int64(local.ID) || bindings[1].GetId() != int64(ldap.ID) || bindings[2].GetId() != int64(oidc.ID) {
		t.Fatalf("unexpected deterministic order: %d, %d, %d", bindings[0].GetId(), bindings[1].GetId(), bindings[2].GetId())
	}
	if bindings[0].CredentialConfigured == nil || !bindings[0].GetCredentialConfigured() {
		t.Fatalf("local summary = %+v, want configured user credential", bindings[0])
	}
	if bindings[2].GetProviderUnionId() != oidc.ProviderUnionID || bindings[2].GetProviderStatus() != adminv1.AuthProvider_DISABLED {
		t.Fatalf("OIDC summary = %+v", bindings[2])
	}
	if bindings[1].CredentialConfigured != nil || bindings[2].CredentialConfigured != nil {
		t.Fatalf("external provider credential state must be absent: LDAP=%+v OIDC=%+v", bindings[1], bindings[2])
	}
}

func TestProjectUserAuthBindingsReportsUnconfiguredLocalCredential(t *testing.T) {
	provider := &lion.AuthProviders{
		ID:           1,
		Code:         "local",
		ProviderType: int(adminv1.AuthProvider_LOCAL),
	}
	identity := testUserAuthIdentity(10, 1001, provider, "local-user-1001")

	bindings, err := projectUserAuthBindings(context.Background(), []*lion.UserIdentities{identity})
	if err != nil {
		t.Fatalf("projectUserAuthBindings: %v", err)
	}
	if bindings[0].CredentialConfigured == nil || bindings[0].GetCredentialConfigured() {
		t.Fatalf("credential_configured = %v, want explicit false for LOCAL identity without password", bindings[0].CredentialConfigured)
	}
}

func TestProjectUserAuthBindingsSupportsOAuthProviderTypes(t *testing.T) {
	providerTypes := []adminv1.AuthProvider_Type{
		adminv1.AuthProvider_OAUTH2,
		adminv1.AuthProvider_GITHUB,
		adminv1.AuthProvider_GOOGLE,
		adminv1.AuthProvider_WECHAT,
	}

	for i, providerType := range providerTypes {
		provider := &lion.AuthProviders{
			ID:             i + 1,
			Code:           strings.ToLower(providerType.String()),
			ProviderType:   int(providerType),
			ProviderStatus: int(adminv1.AuthProvider_ACTIVE),
		}
		identity := testUserAuthIdentity(i+10, 1001, provider, "external-subject")
		identity.PasswordHash = "legacy-value-that-must-not-define-external-credential-state"
		bindings, err := projectUserAuthBindings(context.Background(), []*lion.UserIdentities{identity})
		if err != nil {
			t.Fatalf("type %s: %v", providerType, err)
		}
		if got := bindings[0].GetProviderType(); got != providerType {
			t.Fatalf("provider type = %s, want %s", got, providerType)
		}
		if bindings[0].CredentialConfigured != nil {
			t.Fatalf("type %s credential_configured = %v, want absent", providerType, bindings[0].CredentialConfigured)
		}
	}
}

func TestProjectUserAuthBindingsRejectsMissingProviderEdge(t *testing.T) {
	_, err := projectUserAuthBindings(context.Background(), []*lion.UserIdentities{{ID: 1, UserID: 1001}})
	if err == nil || errs.FromError(err).HTTPStatusCode() != 500 {
		t.Fatalf("error = %v, want HTTP 500", err)
	}
	if strings.Contains(err.Error(), "edge") || strings.Contains(err.Error(), "foreign key") {
		t.Fatalf("error leaks internal relation details: %v", err)
	}
}

func TestUserAuthBindingProtoJSONExcludesSecrets(t *testing.T) {
	provider := &lion.AuthProviders{
		ID:              1,
		Code:            "local",
		DisplayName:     "Local password",
		ProviderType:    int(adminv1.AuthProvider_LOCAL),
		ProviderStatus:  int(adminv1.AuthProvider_ACTIVE),
		SecretEncrypted: []byte("provider-secret-test-value"),
	}
	identity := testUserAuthIdentity(10, 1001, provider, "local-user-1001")
	identity.PasswordHash = "password-hash-test-value"
	identity.MfaSecretEncrypted = []byte("mfa-secret-test-value")
	identity.MfaRecoveryCodesEncrypted = []byte("mfa-recovery-test-value")
	identity.AccessTokenEncrypted = []byte("access-token-test-value")
	identity.RefreshTokenEncrypted = []byte("refresh-token-test-value")

	bindings, err := projectUserAuthBindings(context.Background(), []*lion.UserIdentities{identity})
	if err != nil {
		t.Fatalf("projectUserAuthBindings: %v", err)
	}
	payload, err := protojson.Marshal(&adminv1.ListUserAuthBindingsResponse{Bindings: bindings})
	if err != nil {
		t.Fatalf("protojson.Marshal: %v", err)
	}

	for _, forbidden := range []string{
		"password_hash",
		"password_configured",
		"mfa_enabled",
		"password_changed_at",
		"password_expires_at",
		"last_login_at",
		"access_token_encrypted",
		"refresh_token_encrypted",
		"mfa_secret_encrypted",
		"mfa_recovery_codes_encrypted",
		"secret_encrypted",
		"password-hash-test-value",
		"provider-secret-test-value",
		"mfa-secret-test-value",
		"mfa-recovery-test-value",
		"access-token-test-value",
		"refresh-token-test-value",
	} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("serialized response contains forbidden value %q: %s", forbidden, payload)
		}
	}
}
