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
	"sync"
	"testing"
	"time"

	"entgo.io/ent"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/useridentities"
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
			client := db.OAuth2Clients.Create().SetClientID("mfa-federated-client").SetClientSecretHash("test-only").
				SetScopes([]string{"openid", auth.ScopeFederatedID}).SetGrantTypes([]string{"authorization_code"}).
				SetRedirectUris([]string{"https://client.example.test/callback"}).SaveX(t.Context())
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
			restoreCtx := t.Context() // 子测试清理期间，父测试的上下文仍然有效。
			for i, tc := range []struct {
				name, revoke string
				setup        bool
			}{
				{"verify-active", "", false},
				{"verify-disabled", "disabled", false},
				{"verify-unbound", "unbound", false},
				{"verify-missing-origin", "missing", false},
				{"verify-expired-authorization", "expired", false},
				{"verify-removed-scope", "scope", false},
				{"verify-signing-failure", "signing", false},
				{"setup-active", "", true},
				{"setup-disabled", "disabled", true},
				{"setup-unbound", "unbound", true},
				{"setup-revoked-during-write", "late-disabled", true},
				{"setup-expired-authorization", "expired", true},
				{"setup-removed-scope", "scope", true},
				{"setup-signing-failure", "signing", true},
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
					authorization := FederatedLoginAuthorization{
						ClientID: client.ClientID, RedirectURI: client.RedirectUris[0], Scope: "openid federated:id",
						ExpiresAt: time.Now().Add(2 * time.Minute),
					}
					first, err := api.GetAuthCallback(ContextWithFederatedLoginAuthorization(t.Context(), authorization), &adminv1.GetAuthCallbackRequest{ProviderName: provider.Code, Code: tc.name})
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
					expectedAuthorization := authorization
					expectedAuthorization.Scope = canonicalScope(expectedAuthorization.Scope)
					if challenge.IssuanceContext == nil || challenge.IssuanceContext.authorization == nil || *challenge.IssuanceContext.authorization != expectedAuthorization {
						t.Fatal("MFA 验证或首次绑定改变了原授权参数或截止时间")
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
					case "expired":
						api.mfaChallenges.mu.Lock()
						api.mfaChallenges.entries[challengeID].IssuanceContext.authorization.ExpiresAt = time.Now().Add(-time.Second)
						api.mfaChallenges.mu.Unlock()
					case "scope":
						client.Update().SetScopes([]string{"openid"}).SaveX(t.Context())
						t.Cleanup(func() { client.Update().SetScopes(client.Scopes).SaveX(restoreCtx) })
					case "signing":
						key := db.Credentials.Query().OnlyX(t.Context())
						key.Update().SetCredentialStatus(int(adminv1.Credential_DISABLED)).SaveX(t.Context())
						t.Cleanup(func() { key.Update().SetCredentialStatus(key.CredentialStatus).SaveX(restoreCtx) })
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
						if tc.revoke != "" {
							code = recoveryCode // 授权拒绝或签发失败时，恢复码消费必须回滚。
						}
						result, err = api.VerifyAuthMFA(t.Context(), &adminv1.VerifyAuthMFARequest{ChallengeId: challengeID, TotpCode: code})
					}
					stored := db.UserIdentities.GetX(t.Context(), credential.ID)
					if tc.revoke != "" {
						expected := codes.Unauthenticated
						if tc.revoke == "scope" {
							expected = codes.PermissionDenied
						} else if tc.revoke == "signing" {
							expected = codes.Internal
							if status.Convert(err).Message() != "failed to issue access token" {
								t.Fatalf("内部签发错误未隐藏底层信息：%v", err)
							}
						}
						if status.Code(err) != expected || result.GetAccessToken() != "" {
							t.Fatalf("登录失败时返回了错误的结果：%v", err)
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
						claims := verifiedFederatedTestToken(t, api, result.AccessToken)
						federated := claims.FederatedClaims
						if federated == nil || federated.ConnectorID != provider.Code || federated.UserID == nil || *federated.UserID != tc.name || federated.Username != nil {
							t.Fatal("MFA 丢失了实际认证提供方或授权范围")
						}
					}
					if stored.PasswordHash != credential.PasswordHash {
						t.Fatal("MFA completion replaced the password")
					}
					if _, ok := api.mfaChallenges.Get(challengeID); ok != (tc.revoke == "signing") {
						t.Fatal("仅可重试的内部故障应保留挑战")
					}
				})
			}
		})
	}
}

// Cover both setup entry points without duplicating their existing source-
// revocation fixtures. Separate API instances model distinct pending sessions.
func TestMFASetupStateIntegration(t *testing.T) {
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
			provider := createTestAuthProvider(t, db, "setup-source", adminv1.AuthProvider_OIDC)
			if err := writeGlobalSettingUpdates(t.Context(), db, globalSettingsCategorySecurity, []*adminv1.UpdateGlobalSetting{{SettingKey: globalSettingKeyLoginEnforceMFA, SettingValue: "true"}}, 0, false); err != nil {
				t.Fatal(err)
			}
			type attempt struct {
				api        *KnownAdminAPI
				id, secret string
				login      bool
			}
			for _, tc := range []struct {
				name                                string
				firstLogin, secondLogin, concurrent bool
			}{
				{"login-stale", true, true, false},
				{"self-stale", false, false, false},
				{"mixed-concurrent", true, false, true},
				{"single-consumer", true, false, false},
				{"missing-identity", true, false, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					user := activeIdentityTestUser(t, db, "setup_"+strings.ReplaceAll(tc.name, "-", "_"))
					db.UserIdentities.Create().SetProviderID(provider.ID).SetUserID(user.ID).SetProviderUserID(tc.name).SaveX(t.Context())
					credential := db.UserIdentities.Create().SetProviderID(local.ID).SetUserID(user.ID).SetProviderUserID(user.Username).SetPasswordHash("test-preserved-password").SaveX(t.Context())
					issuance := AccessTokenIssuanceContext{ClientID: "test-client", TTL: 5 * time.Minute}
					newAPI := func() *KnownAdminAPI {
						api := New(WithLionClient(db), WithAESKey([]byte(adminTestAESKey)), WithOIDCProvider("", "test-client", ""))
						t.Cleanup(func() { close(api.mfaChallenges.stopGC) })
						return api
					}
					firstAPI := newAPI()
					gate := func(api *KnownAdminAPI) *adminv1.AuthToken {
						enabled, err := hasUserMFAEnabledIdentity(t.Context(), db, user.ID)
						if err != nil {
							t.Fatal(err)
						}
						token, err := api.applyMFAGateAfterPrimaryAuth(t.Context(), db, user.ID, user.Username, enabled, "", issuance, provider.ID)
						if err != nil || !token.GetMfaRequired() {
							t.Fatalf("MFA gate: %v", err)
						}
						return token
					}
					start := func(api *KnownAdminAPI, login bool) attempt {
						if !login {
							response, err := api.SetupCurrentUserMFA(mfaSessionContext(int64(user.ID), "setup-session"), &adminv1.SetupCurrentUserMFARequest{})
							if err != nil {
								t.Fatal(err)
							}
							return attempt{api, response.ChallengeId, response.Secret, false}
						}
						primary := gate(api)
						if tc.name == "single-consumer" {
							if _, ok := api.mfaChallenges.Acquire(primary.ChallengeId); !ok {
								t.Fatal("cannot reserve challenge")
							}
							if _, err := api.StartAuthMFASetup(t.Context(), &adminv1.StartAuthMFASetupRequest{ChallengeId: primary.ChallengeId}); status.Code(err) != codes.FailedPrecondition {
								t.Fatalf("setup start ignored active consumer: %v", err)
							}
							api.mfaChallenges.Release(primary.ChallengeId)
						}
						response, err := api.StartAuthMFASetup(t.Context(), &adminv1.StartAuthMFASetupRequest{ChallengeId: primary.ChallengeId})
						if err != nil {
							t.Fatal(err)
						}
						return attempt{api, response.SetupChallengeId, response.Secret, true}
					}
					confirm := func(a attempt) error {
						code, err := totp.GenerateCode(a.secret, time.Now())
						if err != nil {
							return err
						}
						if a.login {
							token, err := a.api.ConfirmAuthMFASetup(t.Context(), &adminv1.ConfirmAuthMFASetupRequest{SetupChallengeId: a.id, TotpCode: code})
							if err == nil && token.GetAccessToken() == "" {
								return fmt.Errorf("setup succeeded without a token")
							}
							return err
						}
						response, err := a.api.ConfirmCurrentUserMFA(mfaSessionContext(int64(user.ID), "setup-session"), &adminv1.ConfirmCurrentUserMFARequest{ChallengeId: a.id, TotpCode: code})
						if err == nil && len(response.GetRecoveryCodes()) == 0 {
							return fmt.Errorf("setup succeeded without recovery codes")
						}
						return err
					}
					first := start(firstAPI, tc.firstLogin)
					if tc.name == "missing-identity" {
						db.UserIdentities.DeleteOneID(credential.ID).ExecX(t.Context())
						if err := confirm(first); status.Code(err) != codes.FailedPrecondition {
							t.Fatalf("missing identity accepted: %v", err)
						}
						if db.UserIdentities.Query().Where(useridentities.UserIDEQ(user.ID), useridentities.ProviderIDEQ(local.ID)).ExistX(t.Context()) {
							t.Fatal("confirmation recreated the removed identity")
						}
						if _, ok := firstAPI.mfaChallenges.Get(first.id); ok {
							t.Fatal("invalid setup challenge remains usable")
						}
						return
					}
					if tc.name == "single-consumer" {
						if _, ok := firstAPI.mfaChallenges.Acquire(first.id); !ok {
							t.Fatal("cannot reserve confirmation")
						}
						if err := confirm(first); status.Code(err) != codes.FailedPrecondition {
							t.Fatalf("confirmation ignored active consumer: %v", err)
						}
						firstAPI.mfaChallenges.Release(first.id)
						if _, err := firstAPI.ConfirmAuthMFASetup(t.Context(), &adminv1.ConfirmAuthMFASetupRequest{SetupChallengeId: first.id, TotpCode: "invalid"}); status.Code(err) != codes.Unauthenticated {
							t.Fatalf("invalid code accepted: %v", err)
						}
						if err := confirm(first); err != nil {
							t.Fatal(err)
						}
						verify := gate(firstAPI)
						code, err := totp.GenerateCode(first.secret, time.Now())
						if err != nil {
							t.Fatal(err)
						}
						if _, ok := firstAPI.mfaChallenges.Acquire(verify.ChallengeId); !ok {
							t.Fatal("cannot reserve verification")
						}
						request := &adminv1.VerifyAuthMFARequest{ChallengeId: verify.ChallengeId, TotpCode: code}
						if _, err := firstAPI.VerifyAuthMFA(t.Context(), request); status.Code(err) != codes.FailedPrecondition {
							t.Fatalf("verification ignored active consumer: %v", err)
						}
						firstAPI.mfaChallenges.Release(verify.ChallengeId)
						if token, err := firstAPI.VerifyAuthMFA(t.Context(), request); err != nil || token.GetAccessToken() == "" {
							t.Fatalf("verification did not release its challenge: %v", err)
						}
						if _, err := firstAPI.VerifyAuthMFA(t.Context(), request); status.Code(err) != codes.FailedPrecondition {
							t.Fatalf("verification challenge reused: %v", err)
						}
					} else {
						second := start(newAPI(), tc.secondLogin)
						attempts := []attempt{first, second}
						results := make([]error, 2)
						var committed *lion.UserIdentities
						if tc.concurrent {
							ready := make(chan struct{})
							var wg sync.WaitGroup
							for i := range 2 {
								wg.Go(func() { <-ready; results[i] = confirm(attempts[i]) })
							}
							close(ready)
							wg.Wait()
						} else {
							results[0] = confirm(first)
							committed = db.UserIdentities.GetX(t.Context(), credential.ID)
							results[1] = confirm(second)
						}
						winner := -1
						for i, err := range results {
							if err == nil {
								if winner != -1 {
									t.Fatal("two setup challenges both succeeded")
								}
								winner = i
							} else if status.Code(err) != codes.FailedPrecondition {
								t.Fatalf("unexpected competing setup error: %v", err)
							}
						}
						if winner == -1 {
							t.Fatal("neither setup challenge succeeded")
						}
						stored := db.UserIdentities.GetX(t.Context(), credential.ID)
						secret, err := crypto.DecryptAES([]byte(adminTestAESKey), stored.MfaSecretEncrypted)
						if err != nil || string(secret) != attempts[winner].secret {
							t.Fatal("stored authenticator differs from winning setup")
						}
						if committed != nil && (!bytes.Equal(committed.MfaSecretEncrypted, stored.MfaSecretEncrypted) || !bytes.Equal(committed.MfaRecoveryCodesEncrypted, stored.MfaRecoveryCodesEncrypted)) {
							t.Fatal("stale setup changed the enabled authenticator or recovery codes")
						}
						for _, a := range attempts {
							if _, ok := a.api.mfaChallenges.Get(a.id); ok {
								t.Fatal("completed or rejected setup remains reusable")
							}
						}
					}
					stored := db.UserIdentities.GetX(t.Context(), credential.ID)
					if !stored.MfaEnabled || stored.PasswordHash != credential.PasswordHash {
						t.Fatal("setup changed password or did not enable MFA")
					}
				})
			}
		})
	}
}
