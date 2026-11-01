package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"entgo.io/ent"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion"
	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func createTestLoginSigningKey(t *testing.T, db *lion.Client) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := crypto.EncryptAES([]byte(adminTestAESKey), x509.MarshalPKCS1PrivateKey(key))
	if err != nil {
		t.Fatal(err)
	}
	db.Credentials.Create().SetCode("auth-test-key").
		SetCredentialType(int(adminv1.Credential_KEY_PAIR)).
		SetCredentialAlgorithm(int(adminv1.Credential_RSA)).
		SetCredentialUsage(int(adminv1.Credential_JWKS)).
		SetCredentialVisibility(int(adminv1.Visibility_VISIBILITY_RESTRICTED)).
		SetCredentialStatus(int(adminv1.Credential_ACTIVE)).
		SetCredentialSource(int(adminv1.Credential_SYSTEM)).
		SetPrivateKeyEncrypted(encrypted).SaveX(t.Context())
}

func TestMFAPrimaryAuthenticationIntegration(t *testing.T) {
	for _, backend := range []string{"postgres", "mysql"} {
		t.Run(backend, func(t *testing.T) {
			var db *lion.Client
			if backend == "postgres" {
				db = adminIntegrationClient(t)
			} else {
				db = identityMySQLClient(t)
			}
			createTestLoginSigningKey(t, db)
			local := createTestAuthProvider(t, db, "local", adminv1.AuthProvider_LOCAL)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/token" {
					_ = r.ParseForm()
					_ = json.NewEncoder(w).Encode(map[string]string{"access_token": r.Form.Get("code"), "token_type": "Bearer"})
				} else {
					_ = json.NewEncoder(w).Encode(map[string]string{"sub": strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")})
				}
			}))
			t.Cleanup(server.Close)
			config, err := json.Marshal(oauthConfigData{ClientID: "test-client", AuthorizationEndpoint: server.URL + "/authorize", TokenEndpoint: server.URL + "/token", UserinfoEndpoint: server.URL + "/userinfo"})
			if err != nil {
				t.Fatal(err)
			}
			for i, tc := range []struct {
				name, revoke string
				setup        bool
			}{
				{"verify-active", "", false},
				{"verify-disabled", "disabled", false},
				{"verify-unbound", "unbound", false},
				{"verify-missing-origin", "missing", false},
				{"setup-active", "", true},
				{"setup-disabled", "disabled", true},
				{"setup-unbound", "unbound", true},
				{"setup-revoked-during-write", "late-disabled", true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					provider := createTestAuthProvider(t, db, fmt.Sprintf("mfa-source-%d", i), adminv1.AuthProvider_OAUTH2)
					provider.Update().SetConfig(config).SaveX(t.Context())
					user := activeIdentityTestUser(t, db, fmt.Sprintf("mfa_user_%d", i))
					source := db.UserIdentities.Create().SetProviderID(provider.ID).SetUserID(user.ID).SetProviderUserID(tc.name).SaveX(t.Context())
					const secret = "JBSWY3DPEHPK3PXP"
					secretEnc, err := crypto.EncryptAES([]byte(adminTestAESKey), []byte(secret))
					if err != nil {
						t.Fatal(err)
					}
					const recoveryCode = "test-only-recovery-code"
					recoveryEnc, err := encryptRecoveryCodes([]byte(adminTestAESKey), []string{recoveryCode})
					if err != nil {
						t.Fatal(err)
					}
					credential := db.UserIdentities.Create().SetProviderID(local.ID).SetUserID(user.ID).SetProviderUserID(user.Username).
						SetPasswordHash("test-existing-hash").SetMfaEnabled(!tc.setup).SetMfaSecretEncrypted(secretEnc).SetMfaRecoveryCodesEncrypted(recoveryEnc).SaveX(t.Context())
					if err := writeGlobalSettingUpdates(t.Context(), db, globalSettingsCategorySecurity, []*adminv1.UpdateGlobalSetting{{SettingKey: globalSettingKeyLoginEnforceMFA, SettingValue: strconv.FormatBool(tc.setup)}}, 0, false); err != nil {
						t.Fatal(err)
					}
					api := New(WithLionClient(db), WithAESKey([]byte(adminTestAESKey)), WithOIDCProvider("", "test-client", ""))
					t.Cleanup(func() { close(api.mfaChallenges.stopGC) })
					first, err := api.GetAuthCallback(t.Context(), &adminv1.GetAuthCallbackRequest{ProviderName: provider.Code, Code: tc.name})
					if err != nil || !first.GetMfaRequired() || first.GetAccessToken() != "" {
						t.Fatalf("primary authentication did not require MFA: %v", err)
					}
					challengeID, totpSecret := first.ChallengeId, secret
					if tc.setup {
						started, err := api.StartAuthMFASetup(t.Context(), &adminv1.StartAuthMFASetupRequest{ChallengeId: challengeID})
						if err != nil {
							t.Fatal(err)
						}
						challengeID, totpSecret = started.SetupChallengeId, started.Secret
					}
					challenge, ok := api.mfaChallenges.Get(challengeID)
					if !ok || challenge.PrimaryAuth != (mfaPrimaryAuth{ProviderID: provider.ID, IdentityID: source.ID}) {
						t.Fatal("challenge lost its primary authentication identity")
					}
					switch tc.revoke {
					case "disabled":
						provider.Update().SetProviderStatus(int(adminv1.AuthProvider_DISABLED)).SaveX(t.Context())
					case "unbound":
						db.UserIdentities.DeleteOneID(source.ID).ExecX(t.Context())
					case "missing":
						api.mfaChallenges.mu.Lock()
						api.mfaChallenges.entries[challengeID].PrimaryAuth = mfaPrimaryAuth{}
						api.mfaChallenges.mu.Unlock()
					}
					code, err := totp.GenerateCode(totpSecret, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					var result *adminv1.AuthToken
					if tc.revoke == "late-disabled" {
						// Revoke after the initial transaction check to exercise the
						// final root-client check and rollback of the setup write.
						db.UserIdentities.Use(func(next ent.Mutator) ent.Mutator {
							return ent.MutateFunc(func(ctx context.Context, mutation ent.Mutation) (ent.Value, error) {
								if m, ok := mutation.(*lion.UserIdentitiesMutation); ok {
									if enabled, set := m.MfaEnabled(); set && enabled {
										if _, err := provider.Update().SetProviderStatus(int(adminv1.AuthProvider_DISABLED)).Save(ctx); err != nil {
											return nil, err
										}
									}
								}
								return next.Mutate(ctx, mutation)
							})
						})
					}
					if tc.setup {
						result, err = api.ConfirmAuthMFASetup(t.Context(), &adminv1.ConfirmAuthMFASetupRequest{SetupChallengeId: challengeID, TotpCode: code})
					} else {
						if tc.revoke == "disabled" {
							code = recoveryCode // Revocation must not consume a recovery code.
						}
						result, err = api.VerifyAuthMFA(t.Context(), &adminv1.VerifyAuthMFARequest{ChallengeId: challengeID, TotpCode: code})
					}
					stored := db.UserIdentities.GetX(t.Context(), credential.ID)
					if tc.revoke != "" {
						if status.Code(err) != codes.Unauthenticated || result.GetAccessToken() != "" {
							t.Fatalf("revoked authentication issued a token: %v", err)
						}
						if stored.MfaEnabled != credential.MfaEnabled || !bytes.Equal(stored.MfaSecretEncrypted, credential.MfaSecretEncrypted) || !bytes.Equal(stored.MfaRecoveryCodesEncrypted, credential.MfaRecoveryCodesEncrypted) {
							t.Fatal("rejected authentication changed MFA or consumed a recovery code")
						}
					} else {
						if err != nil || result.GetAccessToken() == "" {
							t.Fatalf("active authentication failed: %v", err)
						}
						id, name, err := extractUserFromAccessToken(result.AccessToken)
						if err != nil || id != user.ID || name != user.Username || !stored.MfaEnabled {
							t.Fatal("successful authentication changed the target user")
						}
					}
					if stored.PasswordHash != credential.PasswordHash {
						t.Fatal("MFA completion replaced the password")
					}
					if _, ok := api.mfaChallenges.Get(challengeID); ok {
						t.Fatal("completed or revoked challenge remains reusable")
					}
				})
			}
		})
	}
}
