package admin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"entgo.io/ent"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-kit/pkg/auth"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	mysqlDriver "github.com/go-sql-driver/mysql"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/globalsettings"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"golang.org/x/oauth2"
)

var identityFixtureSequence atomic.Uint64

// PostgreSQL uses the existing temporary-database fixture. MySQL opts in with
// GRPC_KIT_IDENTITY_MYSQL_DSN and likewise creates/drops only a fresh database.
func identityMySQLClient(t *testing.T) *lion.Client {
	t.Helper()
	dsn := os.Getenv("GRPC_KIT_IDENTITY_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set GRPC_KIT_IDENTITY_MYSQL_DSN to enable real MySQL integration")
	}
	config, err := mysqlDriver.ParseDSN(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.DBName = ""
	config.ParseTime = true
	server, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("identity_test_%d", time.Now().UnixNano())
	if _, err := server.ExecContext(t.Context(), "CREATE DATABASE "+name+" CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci"); err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = server.Exec("DROP DATABASE " + name); _ = server.Close() })
	config.DBName = name
	db, err := lion.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Schema.Create(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Ent's MySQL tables default to a binary collation independently of the
	// database default. Exercise the supported case-insensitive deployment too.
	connection, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	_, err = connection.ExecContext(t.Context(), "ALTER TABLE lion_users MODIFY username VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL")
	_ = connection.Close()
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func identityFixture(t *testing.T, db *lion.Client) (*socialUsers, string) {
	t.Helper()
	seq := identityFixtureSequence.Add(1)
	provider := createTestAuthProvider(t, db, fmt.Sprintf("corp%d", seq), adminv1.AuthProvider_OIDC)
	setIdentityTestPolicy(t, db, usernameExternalThenPrefixed, false, true)
	return newTestSocialUsers(db, provider), fmt.Sprintf("Alice.%d", seq)
}

func setIdentityTestPolicy(t *testing.T, db *lion.Client, strategy usernameStrategy, username, contact bool) {
	t.Helper()
	updates := []*adminv1.UpdateGlobalSetting{
		{SettingKey: globalSettingKeyIdentityUsernameStrategy, SettingValue: string(strategy)},
		{SettingKey: globalSettingKeyIdentityAutoLinkByUsername, SettingValue: fmt.Sprint(username)},
		{SettingKey: globalSettingKeyIdentityAutoLinkByVerifiedContact, SettingValue: fmt.Sprint(contact)},
	}
	if err := writeGlobalSettingUpdates(t.Context(), db, globalSettingsCategorySecurity, updates, 0, true); err != nil {
		t.Fatal(err)
	}
}

func activeIdentityTestUser(t *testing.T, db *lion.Client, name string) *lion.Users {
	t.Helper()
	user, err := db.Users.Create().SetUsername(name).SetUserStatus(int(adminv1.User_ACTIVE)).Save(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func identityTestLogin(ctx context.Context, s *socialUsers, subject, name string) (int, error) {
	return s.upsertUserOIDC(ctx, &oauth2.Token{}, externalUserClaims{ProviderSubject: subject, Username: name})
}

func TestExternalIdentityProvisioningIntegration(t *testing.T) {
	for _, backend := range []string{"postgres", "mysql"} {
		t.Run(backend, func(t *testing.T) {
			var db *lion.Client
			if backend == "postgres" {
				db = adminIntegrationClient(t)
			} else {
				db = identityMySQLClient(t)
			}
			runExternalIdentityIntegration(t, db, backend)
		})
	}
}

func runExternalIdentityIntegration(t *testing.T, db *lion.Client, backend string) {
	t.Run("first-policy-writes-are-serializable", func(t *testing.T) {
		if count := db.GlobalSettings.Query().CountX(t.Context()); count != 0 {
			t.Fatalf("fixture not empty: %d", count)
		}
		api := New(WithLionClient(db))
		start := make(chan struct{})
		results := make(chan error, 2)
		var wg sync.WaitGroup
		for _, item := range []*adminv1.UpdateGlobalSetting{
			{SettingKey: globalSettingKeyIdentityUsernameStrategy, SettingValue: "provider_prefixed"},
			{SettingKey: globalSettingKeyIdentityAutoLinkByUsername, SettingValue: "true"},
		} {
			wg.Go(func() {
				<-start
				_, err := api.UpdateGlobalSettings(configSuperadminTestContext(), &adminv1.UpdateGlobalSettingsRequest{Category: globalSettingsCategorySecurity, Updates: []*adminv1.UpdateGlobalSetting{item}})
				results <- err
			})
		}
		close(start)
		wg.Wait()
		close(results)
		successes := 0
		for err := range results {
			if err == nil {
				successes++
			}
		}
		if successes != 1 {
			t.Fatalf("first policy writes: %d successes", successes)
		}
		if _, err := readIdentityPolicy(t.Context(), db.GlobalSettings.Query()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("original-prefix-suffix-strict", func(t *testing.T) {
		s, name := identityFixture(t, db)
		first, err := identityTestLogin(t.Context(), s, "one", name)
		if err != nil {
			t.Fatal(err)
		}
		user := db.Users.GetX(t.Context(), first)
		if user.Username != name || user.UserStatus != int(adminv1.User_ACTIVE) {
			t.Fatalf("new user: %+v", user)
		}
		second, err := identityTestLogin(t.Context(), s, "two", name)
		if err != nil {
			t.Fatal(err)
		}
		if got := db.Users.GetX(t.Context(), second).Username; got != s.ProviderName+"_"+name {
			t.Fatalf("prefix: %q", got)
		}
		third, err := identityTestLogin(t.Context(), s, "three", name)
		if err != nil {
			t.Fatal(err)
		}
		if got := db.Users.GetX(t.Context(), third).Username; got != s.ProviderName+"_"+name+"_2" {
			t.Fatalf("suffix: %q", got)
		}
		before := db.Users.Query().CountX(t.Context())
		setIdentityTestPolicy(t, db, usernameExternalStrict, false, true)
		if _, err := identityTestLogin(t.Context(), s, "strict", name); !errors.Is(err, errExternalUsernameConflict) {
			t.Fatalf("strict err=%v", err)
		}
		if db.Users.Query().CountX(t.Context()) != before {
			t.Fatal("failed strict login created user")
		}
	})
	t.Run("allocation-limit-and-long-prefix", func(t *testing.T) {
		s, name := identityFixture(t, db)
		activeIdentityTestUser(t, db, name)
		creates := make([]*lion.UsersCreate, 0, 100)
		for i := range 100 {
			candidate := s.ProviderName + "_" + name
			if i > 0 {
				candidate = fmt.Sprintf("%s_%d", candidate, i+1)
			}
			creates = append(creates, db.Users.Create().SetUsername(candidate).SetUserStatus(int(adminv1.User_ACTIVE)))
		}
		db.Users.CreateBulk(creates...).SaveX(t.Context())
		before := db.Users.Query().CountX(t.Context())
		if _, err := identityTestLogin(t.Context(), s, "exhausted", name); err == nil {
			t.Fatal("accepted exhausted names")
		}
		if db.Users.Query().CountX(t.Context()) != before {
			t.Fatal("exhaustion created user")
		}
		long := strings.Repeat("a", 255)
		activeIdentityTestUser(t, db, long)
		if _, err := identityTestLogin(t.Context(), s, "long", long); !errors.Is(err, errExternalUsernameConflict) {
			t.Fatalf("long prefix err=%v", err)
		}
	})
	t.Run("explicit-whitespace-is-not-an-account-alias", func(t *testing.T) {
		s, name := identityFixture(t, db)
		target := activeIdentityTestUser(t, db, name)
		setIdentityTestPolicy(t, db, usernameExternalThenPrefixed, true, false)
		claims := &auth.IDTokenClaims{CommonClaims: auth.CommonClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: "space"}, PreferredUsername: " " + name + " "}}
		_, err := s.upsertUserOIDC(t.Context(), &oauth2.Token{}, externalUserClaimsFromIDToken(claims))
		if !errors.Is(err, errExternalUsernameConflict) {
			t.Fatalf("ambiguous name accepted: %v", err)
		}
		if db.UserIdentities.Query().Where(useridentities.UserIDEQ(target.ID)).CountX(t.Context()) != 0 {
			t.Fatal("whitespace identity associated")
		}
	})
	t.Run("legacy-wechat-rejects-collision-without-leaking-transaction", func(t *testing.T) {
		s, name := identityFixture(t, db)
		wx := createTestAuthProvider(t, db, s.ProviderName+"wx", adminv1.AuthProvider_WECHAT)
		ws := newTestSocialUsers(db, wx)
		setIdentityTestPolicy(t, db, usernameProviderPrefixed, false, true)
		activeIdentityTestUser(t, db, strings.ToLower(ws.ProviderName+"_"+name))
		if _, err := ws.upsertUserWechat(t.Context(), &wechatCode2SessionResponse{Openid: name}); !errors.Is(err, errExternalUsernameConflict) {
			t.Fatalf("legacy collision=%v", err)
		}
		if _, err := ws.upsertUserWechat(t.Context(), &wechatCode2SessionResponse{Openid: name + "other"}); err != nil {
			t.Fatalf("subsequent transaction failed: %v", err)
		}
	})
	t.Run("static-names-reserved-even-without-database-user", func(t *testing.T) {
		s, name := identityFixture(t, db)
		reserved := StaticUsers{
			&StaticUser{Username: name, UserID: 999999},
			&StaticUser{Username: s.ProviderName + "_" + name, UserID: 999998},
		}
		s.staticUsers = &reserved
		id, err := identityTestLogin(t.Context(), s, "unbound-static-name", name)
		if err != nil {
			t.Fatal(err)
		}
		if got := db.Users.GetX(t.Context(), id).Username; got != s.ProviderName+"_"+name+"_2" {
			t.Fatalf("static name reused: %q", got)
		}
		setIdentityTestPolicy(t, db, usernameExternalThenPrefixed, true, false)
		if _, err := identityTestLogin(t.Context(), s, "other-static-name", name); !errors.Is(err, errExternalUsernameConflict) {
			t.Fatalf("reserved name associated: %v", err)
		}
	})
	t.Run("all-association-switch-combinations", func(t *testing.T) {
		for _, username := range []bool{false, true} {
			for _, contact := range []bool{false, true} {
				s, name := identityFixture(t, db)
				email := strings.ToLower(name) + "@example.test"
				canonical, err := canonicalizeEmailIdentifier(email)
				if err != nil {
					t.Fatal(err)
				}
				target, err := db.Users.Create().SetUsername(name).SetUserStatus(int(adminv1.User_ACTIVE)).SetEmailHash(canonical.Hash).SetEmailVerified(true).Save(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				setIdentityTestPolicy(t, db, usernameExternalThenPrefixed, username, contact)
				before := db.Users.Query().CountX(t.Context())
				id, err := s.upsertUserOIDC(t.Context(), &oauth2.Token{}, externalUserClaims{ProviderSubject: "switches", Username: name, Email: email, EmailVerified: true})
				if username || contact {
					if err != nil || id != target.ID {
						t.Fatalf("username=%v contact=%v id=%d err=%v", username, contact, id, err)
					}
				} else if err == nil {
					t.Fatal("disabled association bypassed unique email ownership")
				}
				if db.Users.Query().CountX(t.Context()) != before {
					t.Fatal("association or failed provisioning left user")
				}
			}
		}
	})
	t.Run("strict-contact-link-needs-no-new-username", func(t *testing.T) {
		s, name := identityFixture(t, db)
		email := strings.ToLower(name) + "@example.test"
		canonical, _ := canonicalizeEmailIdentifier(email)
		target := db.Users.Create().SetUsername(name).SetUserStatus(int(adminv1.User_ACTIVE)).SetEmailHash(canonical.Hash).SetEmailVerified(true).SaveX(t.Context())
		setIdentityTestPolicy(t, db, usernameExternalStrict, false, true)
		id, err := s.upsertUserOIDC(t.Context(), &oauth2.Token{}, externalUserClaims{ProviderSubject: "opaque", Username: "opaque", UsernameIsFallback: true, Email: email, EmailVerified: true})
		if err != nil || id != target.ID {
			t.Fatalf("contact association required new username: %d %v", id, err)
		}
	})
	t.Run("verified-phone-association", func(t *testing.T) {
		s, name := identityFixture(t, db)
		phone, err := canonicalizeE164PhoneIdentifier("+8613900001234")
		if err != nil {
			t.Fatal(err)
		}
		target := db.Users.Create().SetUsername(name).SetUserStatus(int(adminv1.User_ACTIVE)).SetPhoneNumberHash(phone.Hash).SetPhoneNumberVerified(true).SaveX(t.Context())
		id, err := s.upsertUserOIDC(t.Context(), &oauth2.Token{}, externalUserClaims{ProviderSubject: "phone", Username: name + ".other", PhoneNumber: "+8613900001234", PhoneNumberVerified: true})
		if err != nil || id != target.ID {
			t.Fatalf("phone association=%d err=%v", id, err)
		}
	})
	t.Run("association-preserves-password-and-mfa", func(t *testing.T) {
		s, name := identityFixture(t, db)
		target := activeIdentityTestUser(t, db, name)
		local := createTestAuthProvider(t, db, s.ProviderName+"local", adminv1.AuthProvider_LOCAL)
		credential := db.UserIdentities.Create().SetUserID(target.ID).SetProviderID(local.ID).SetProviderUserID("local-subject").SetPasswordHash("test-existing-hash").SetMfaEnabled(true).SetMfaSecretEncrypted([]byte("test-existing-encrypted-secret")).SaveX(t.Context())
		setIdentityTestPolicy(t, db, usernameExternalThenPrefixed, true, false)
		before := db.Users.Query().CountX(t.Context())
		id, err := identityTestLogin(t.Context(), s, "mfa-account", name)
		if err != nil || id != target.ID {
			t.Fatalf("association=%d err=%v", id, err)
		}
		identity := db.UserIdentities.Query().Where(useridentities.ProviderIDEQ(s.AuthProvider.ID)).OnlyX(t.Context())
		if db.Users.Query().CountX(t.Context()) != before || identity.UserID != id || identity.ProviderUserID != "mfa-account" {
			t.Fatal("association created duplicate user or incorrect binding")
		}
		got := db.UserIdentities.GetX(t.Context(), credential.ID)
		if got.PasswordHash != credential.PasswordHash || !got.MfaEnabled || string(got.MfaSecretEncrypted) != string(credential.MfaSecretEncrypted) {
			t.Fatal("existing credential changed")
		}
		enabled, err := hasUserMFAEnabledIdentity(t.Context(), db, id)
		if err != nil || !enabled {
			t.Fatalf("MFA identity lost: %v %v", enabled, err)
		}
		api := New(WithLionClient(db))
		issuance := AccessTokenIssuanceContext{ClientID: "test-client", TTL: time.Hour}
		gate, err := api.applyMFAGateAfterPrimaryAuth(t.Context(), db, id, name, enabled, "test-provisional-token", issuance, s.AuthProvider.ID)
		if err != nil || !gate.GetMfaRequired() || gate.GetAccessToken() != "" || gate.GetChallengeId() == "" {
			t.Fatalf("MFA gate bypassed: %+v err=%v", gate, err)
		}

	})
	t.Run("identity-failure-rolls-back-user", func(t *testing.T) {
		s, name := identityFixture(t, db)
		forced := errors.New("test identity write failure")
		db.UserIdentities.Use(func(next ent.Mutator) ent.Mutator {
			return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
				if mutation, ok := m.(*lion.UserIdentitiesMutation); ok {
					provider, _ := mutation.ProviderID()
					subject, _ := mutation.ProviderUserID()
					if provider == s.AuthProvider.ID && subject == "force-failure" {
						return nil, forced
					}
				}
				return next.Mutate(ctx, m)
			})
		})
		beforeUsers := db.Users.Query().CountX(t.Context())
		beforeMembers := db.UserMemberships.Query().CountX(t.Context())
		if _, err := identityTestLogin(t.Context(), s, "force-failure", name); !errors.Is(err, forced) {
			t.Fatalf("err=%v", err)
		}
		if db.Users.Query().CountX(t.Context()) != beforeUsers || db.UserMemberships.Query().CountX(t.Context()) != beforeMembers {
			t.Fatal("partial provisioning survived rollback")
		}
		if _, err := identityTestLogin(t.Context(), s, "next-request", name); err != nil {
			t.Fatalf("transaction not reusable: %v", err)
		}
	})
	t.Run("conflicting-candidates-rollback", func(t *testing.T) {
		s, name := identityFixture(t, db)
		activeIdentityTestUser(t, db, name)
		email := strings.ToLower(name) + "@example.test"
		canonical, _ := canonicalizeEmailIdentifier(email)
		if _, err := db.Users.Create().SetUsername(name + ".contact").SetUserStatus(int(adminv1.User_ACTIVE)).SetEmailHash(canonical.Hash).SetEmailVerified(true).Save(t.Context()); err != nil {
			t.Fatal(err)
		}
		setIdentityTestPolicy(t, db, usernameExternalThenPrefixed, true, true)
		before := db.Users.Query().CountX(t.Context())
		_, err := s.upsertUserOIDC(t.Context(), &oauth2.Token{}, externalUserClaims{ProviderSubject: "conflict", Username: name, Email: email, EmailVerified: true})
		if !errors.Is(err, errExternalVerifiedIdentifiersConflict) {
			t.Fatalf("err=%v", err)
		}
		if db.Users.Query().CountX(t.Context()) != before || db.UserIdentities.Query().Where(useridentities.ProviderIDEQ(s.AuthProvider.ID)).CountX(t.Context()) != 0 {
			t.Fatal("partial conflicting association")
		}
	})
	t.Run("protected-and-disabled-targets", func(t *testing.T) {
		for _, variant := range []string{"disabled", "deleted", "admin-type", "system-type", "admin-role", "superadmin-role", "static-name", "static-id"} {
			t.Run(variant, func(t *testing.T) {
				s, name := identityFixture(t, db)
				target := activeIdentityTestUser(t, db, name)
				switch variant {
				case "disabled":
					target.Update().SetUserStatus(int(adminv1.User_DISABLED)).SaveX(t.Context())
				case "deleted":
					target.Update().SetDeletedAt(time.Now()).SaveX(t.Context())
				case "admin-type":
					target.Update().SetUserType(int(adminv1.User_ADMIN)).SaveX(t.Context())
				case "system-type":
					target.Update().SetUserType(int(adminv1.User_SYSTEM)).SaveX(t.Context())
				case "admin-role", "superadmin-role":
					code := seedRoleCode(adminv1.RoleCode_ROLE_CODE_ADMIN)
					if variant == "superadmin-role" {
						code = seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN)
					}
					role := db.Roles.Create().SetCode(code).SetDisplayName(code).SetRoleStatus(int(adminv1.Role_ACTIVE)).SaveX(t.Context())
					db.PrincipalRoles.Create().SetPrincipalType(1).SetPrincipalID(target.ID).SetRoleID(role.ID).SaveX(t.Context())
				case "static-name":
					static := StaticUsers{&StaticUser{Username: name, UserID: 999999}}
					s.staticUsers = &static
				case "static-id":
					static := StaticUsers{&StaticUser{Username: name + ".static", UserID: int64(target.ID)}}
					s.staticUsers = &static
				}
				setIdentityTestPolicy(t, db, usernameExternalThenPrefixed, true, false)
				_, err := identityTestLogin(t.Context(), s, "protected", name)
				if !errors.Is(err, errExternalUsernameConflict) {
					t.Fatalf("err=%v", err)
				}
				if db.UserIdentities.Query().Where(useridentities.ProviderIDEQ(s.AuthProvider.ID)).CountX(t.Context()) != 0 {
					t.Fatal("protected target bound")
				}
			})
		}
	})
	t.Run("provider-already-bound", func(t *testing.T) {
		s, name := identityFixture(t, db)
		target := activeIdentityTestUser(t, db, name)
		db.UserIdentities.Create().SetProviderID(s.AuthProvider.ID).SetUserID(target.ID).SetProviderUserID("original").SaveX(t.Context())
		setIdentityTestPolicy(t, db, usernameExternalThenPrefixed, true, false)
		if _, err := identityTestLogin(t.Context(), s, "other", name); !errors.Is(err, errExternalIdentityAlreadyBound) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("existing-binding-precedes-policy-and-new-name", func(t *testing.T) {
		s, name := identityFixture(t, db)
		old := activeIdentityTestUser(t, db, s.ProviderName+"_"+name)
		activeIdentityTestUser(t, db, name)
		db.UserIdentities.Create().SetProviderID(s.AuthProvider.ID).SetUserID(old.ID).SetProviderUserID("stable").SaveX(t.Context())
		before := db.Users.Query().CountX(t.Context())
		for _, strategy := range []usernameStrategy{usernameExternalThenPrefixed, usernameExternalStrict, usernameProviderPrefixed} {
			setIdentityTestPolicy(t, db, strategy, false, true)
			id, err := identityTestLogin(t.Context(), s, "stable", "invalid @ new name")
			if err != nil || id != old.ID {
				t.Fatalf("strategy=%s id=%d err=%v", strategy, id, err)
			}
		}
		db.GlobalSettings.Update().Where(globalsettings.SettingKeyEQ(globalSettingKeyIdentityUsernameStrategy)).SetSettingValue("corrupted").ExecX(t.Context())
		if id, err := identityTestLogin(t.Context(), s, "stable", name); err != nil || id != old.ID {
			t.Fatalf("existing binding depended on policy: %d %v", id, err)
		}
		if db.Users.GetX(t.Context(), old.ID).Username != old.Username || db.Users.Query().CountX(t.Context()) != before || db.UserIdentities.Query().Where(useridentities.ProviderIDEQ(s.AuthProvider.ID)).CountX(t.Context()) != 1 {
			t.Fatal("existing identity changed")
		}
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		s.privateKey = key
		s.kid = "identity-test"
		s.issuanceContext = AccessTokenIssuanceContext{ClientID: "test-client", TTL: time.Hour}
		raw, _, err := s.issueAccessTokenForUserID(t.Context(), old.ID)
		if err != nil {
			t.Fatal(err)
		}
		claims := &auth.AccessTokenClaims{}
		if _, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil }, jwt.WithValidMethods([]string{"RS256"})); err != nil {
			t.Fatal(err)
		}
		if claims.Subject != strconv.Itoa(old.ID) || claims.PreferredUsername != old.Username {
			t.Fatalf("changed downstream identity: %+v", claims)
		}

	})
	t.Run("subject-fallback-and-wechat", func(t *testing.T) {
		s, name := identityFixture(t, db)
		activeIdentityTestUser(t, db, name)
		setIdentityTestPolicy(t, db, usernameExternalThenPrefixed, true, false)
		id, err := s.upsertUserOIDC(t.Context(), &oauth2.Token{}, externalUserClaims{ProviderSubject: name, Username: name, UsernameIsFallback: true})
		if err != nil {
			t.Fatal(err)
		}
		if got := db.Users.GetX(t.Context(), id).Username; got == name {
			t.Fatal("subject fallback associated by username")
		}
		wx := createTestAuthProvider(t, db, s.ProviderName+"wx", adminv1.AuthProvider_WECHAT)
		ws := newTestSocialUsers(db, wx)
		id, err = ws.upsertUserWechat(t.Context(), &wechatCode2SessionResponse{Openid: name, Unionid: "union-one", SessionKey: "test-session"})
		if err != nil {
			t.Fatal(err)
		}
		if db.Users.GetX(t.Context(), id).Username == name {
			t.Fatal("OpenID treated as username proof")
		}
		if id2, err := ws.upsertUserWechat(t.Context(), &wechatCode2SessionResponse{Openid: name, Unionid: "union-two"}); err != nil || id2 != id {
			t.Fatalf("wechat repeat=%d err=%v", id2, err)
		}
		identity := db.UserIdentities.Query().Where(useridentities.ProviderIDEQ(wx.ID)).OnlyX(t.Context())
		if identity.ProviderUnionID != "union-one" {
			t.Fatal("UnionID overwritten")
		}
	})
	t.Run("collation-does-not-prove-identity", func(t *testing.T) {
		s, name := identityFixture(t, db)
		target := activeIdentityTestUser(t, db, strings.ToLower(name))
		setIdentityTestPolicy(t, db, usernameExternalThenPrefixed, true, false)
		id, err := identityTestLogin(t.Context(), s, "case", name)
		if err != nil || id == target.ID {
			t.Fatalf("collation associated: id=%d err=%v", id, err)
		}
		got := db.Users.GetX(t.Context(), id).Username
		if backend == "mysql" && got != s.ProviderName+"_"+name {
			t.Fatalf("mysql collation fallback=%q", got)
		}
		if backend == "postgres" && got != name {
			t.Fatalf("postgres exact spelling=%q", got)
		}
	})
	t.Run("same-subject-concurrency", func(t *testing.T) {
		s, name := identityFixture(t, db)
		before := db.Users.Query().CountX(t.Context())
		type result struct {
			id  int
			err error
		}
		results := make(chan result, 8)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				<-start
				id, err := identityTestLogin(t.Context(), s, "concurrent", name)
				results <- result{id, err}
			})
		}
		close(start)
		wg.Wait()
		close(results)
		chosen := 0
		for result := range results {
			if result.err != nil {
				t.Fatal(result.err)
			}
			if chosen == 0 {
				chosen = result.id
			}
			if chosen != result.id {
				t.Fatal("duplicate identity users")
			}
		}
		if db.Users.Query().CountX(t.Context()) != before+1 || db.UserIdentities.Query().Where(useridentities.ProviderIDEQ(s.AuthProvider.ID)).CountX(t.Context()) != 1 {
			t.Fatal("concurrent orphan or duplicate")
		}
	})
	t.Run("different-subject-name-race", func(t *testing.T) {
		s, name := identityFixture(t, db)
		before := db.Users.Query().CountX(t.Context())
		type result struct {
			id  int
			err error
		}
		results := make(chan result, 4)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range 4 {
			wg.Go(func() {
				<-start
				id, err := identityTestLogin(t.Context(), s, fmt.Sprint(i), name)
				results <- result{id, err}
			})
		}
		close(start)
		wg.Wait()
		close(results)
		ids := map[int]bool{}
		for result := range results {
			if result.err != nil {
				continue
			}
			if ids[result.id] {
				t.Fatal("different subjects shared a user without association")
			}
			ids[result.id] = true
		}
		if len(ids) == 0 || db.Users.Query().CountX(t.Context()) != before+len(ids) || db.UserIdentities.Query().Where(useridentities.ProviderIDEQ(s.AuthProvider.ID)).CountX(t.Context()) != len(ids) {
			t.Fatal("name race left orphan or duplicate")
		}
	})
	t.Run("disabled-provider-and-credential-failure", func(t *testing.T) {
		s, name := identityFixture(t, db)
		before := db.Users.Query().CountX(t.Context())
		s.aesKey = []byte("invalid")
		if _, err := s.upsertUserOIDC(t.Context(), &oauth2.Token{AccessToken: "test-only"}, externalUserClaims{ProviderSubject: "bad-key", Username: name}); err == nil {
			t.Fatal("accepted failed encryption")
		}
		if db.Users.Query().CountX(t.Context()) != before {
			t.Fatal("failed encryption left a user")
		}
		s.AuthProvider.Update().SetProviderStatus(int(adminv1.AuthProvider_DISABLED)).SaveX(t.Context())
		if _, err := identityTestLogin(t.Context(), s, "disabled", name); !errors.Is(err, errExternalLoginRejected) {
			t.Fatalf("disabled provider err=%v", err)
		}
	})
	t.Run("policy-update-atomic-and-concurrent", func(t *testing.T) {
		setIdentityTestPolicy(t, db, usernameExternalThenPrefixed, false, true)
		api := New(WithLionClient(db))
		call := func(updates ...*adminv1.UpdateGlobalSetting) error {
			_, err := api.UpdateGlobalSettings(configSuperadminTestContext(), &adminv1.UpdateGlobalSettingsRequest{Category: globalSettingsCategorySecurity, Updates: updates})
			return err
		}
		if err := call(&adminv1.UpdateGlobalSetting{SettingKey: globalSettingKeyIdentityAutoLinkByVerifiedContact, SettingValue: "false"}, &adminv1.UpdateGlobalSetting{SettingKey: globalSettingKeyIdentityUsernameStrategy, SettingValue: "invalid"}); err == nil {
			t.Fatal("accepted invalid strategy")
		}
		policy, err := readIdentityPolicy(t.Context(), db.GlobalSettings.Query())
		if err != nil || !policy.LinkByContact {
			t.Fatalf("partial update: %+v %v", policy, err)
		}
		failures := make(chan error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() {
			<-start
			failures <- call(&adminv1.UpdateGlobalSetting{SettingKey: globalSettingKeyIdentityUsernameStrategy, SettingValue: "provider_prefixed"})
		})
		wg.Go(func() {
			<-start
			failures <- call(&adminv1.UpdateGlobalSetting{SettingKey: globalSettingKeyIdentityAutoLinkByUsername, SettingValue: "true"})
		})
		close(start)
		wg.Wait()
		close(failures)
		successes := 0
		for err := range failures {
			if err == nil {
				successes++
			}
		}
		if successes != 1 {
			t.Fatalf("expected one winning policy update, got %d", successes)
		}
		if _, err := readIdentityPolicy(t.Context(), db.GlobalSettings.Query()); err != nil {
			t.Fatal(err)
		}
	})
}
