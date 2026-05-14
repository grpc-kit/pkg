package admin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/grpc-kit/pkg/auth"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	_ "github.com/mattn/go-sqlite3"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/enttest"
	"github.com/grpc-kit/pkg/lion/globalsettings"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGlobalSettingsRegistryIncludesInitialSecurityKeys(t *testing.T) {
	tests := []struct {
		category   string
		settingKey string
		valueType  globalSettingValueType
		defaultVal string
	}{
		{category: globalSettingsCategorySecurity, settingKey: globalSettingKeyLoginEnforceMFA, valueType: globalSettingValueTypeBool, defaultVal: "false"},
		{category: globalSettingsCategorySecurity, settingKey: globalSettingKeyLoginAccessTokenTTL, valueType: globalSettingValueTypeDuration, defaultVal: "24h"},
		{category: globalSettingsCategorySecurity, settingKey: globalSettingKeyMFAChallengeTTL, valueType: globalSettingValueTypeDuration, defaultVal: "5m"},
		{category: globalSettingsCategorySecurity, settingKey: globalSettingKeyMFAMaxVerifyAttempts, valueType: globalSettingValueTypeInt, defaultVal: "5"},
		{category: globalSettingsCategorySecurity, settingKey: globalSettingKeyMFARecoveryCodesCount, valueType: globalSettingValueTypeInt, defaultVal: "8"},
		{category: globalSettingsCategorySecurity, settingKey: globalSettingKeyMFATOTPIssuer, valueType: globalSettingValueTypeString, defaultVal: "KnownAdmin"},
	}

	for _, tt := range tests {
		spec, ok := lookupGlobalSettingSpec(tt.category, tt.settingKey)
		if !ok {
			t.Fatalf("missing spec for %s/%s", tt.category, tt.settingKey)
		}
		if spec.ValueType != tt.valueType {
			t.Fatalf("unexpected value type for %s/%s: got=%s want=%s", tt.category, tt.settingKey, spec.ValueType, tt.valueType)
		}
		if spec.DefaultValue != tt.defaultVal {
			t.Fatalf("unexpected default for %s/%s: got=%s want=%s", tt.category, tt.settingKey, spec.DefaultValue, tt.defaultVal)
		}
		if !spec.Protected {
			t.Fatalf("expected protected spec for %s/%s", tt.category, tt.settingKey)
		}
	}
	}

func TestGetLocalMFAPolicyPrefersGlobalSettingOverLegacyProviderConfig(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:global-settings-mfa-prefers-new?mode=memory&cache=shared&_fk=1")
	defer db.Close()

	_, err := db.AuthProviders.Create().
		SetCode("local").
		SetProviderType(int(adminv1.AuthProvider_LOCAL.Number())).
		SetProviderStatus(int(adminv1.AuthProvider_ACTIVE.Number())).
		SetDisplayName("local").
		SetConfig([]byte(`{"enforce_mfa_for_all_users":false}`)).
		Save(ctx)
	if err != nil {
		t.Fatalf("create auth provider failed: %v", err)
	}

	_, err = db.GlobalSettings.Create().
		SetCategory(globalSettingsCategorySecurity).
		SetSettingKey(globalSettingKeyLoginEnforceMFA).
		SetSettingValue("true").
		SetValueType(string(globalSettingValueTypeBool)).
		SetProtected(true).
		Save(ctx)
	if err != nil {
		t.Fatalf("create global setting failed: %v", err)
	}

	a := New(WithLionClient(db))
	enforce, _, err := a.getLocalMFAPolicy(ctx, db)
	if err != nil {
		t.Fatalf("getLocalMFAPolicy failed: %v", err)
	}
	if !enforce {
		t.Fatalf("expected global setting to override legacy provider config")
	}
}

func TestGetLocalMFAPolicyDoesNotFallbackToLegacyProviderConfigWhenGlobalSettingMissing(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:global-settings-mfa-fallback?mode=memory&cache=shared&_fk=1")
	defer db.Close()

	provider, err := db.AuthProviders.Create().
		SetCode("local").
		SetProviderType(int(adminv1.AuthProvider_LOCAL.Number())).
		SetProviderStatus(int(adminv1.AuthProvider_ACTIVE.Number())).
		SetDisplayName("local").
		SetConfig([]byte(`{"enforce_mfa_for_all_users":true}`)).
		Save(ctx)
	if err != nil {
		t.Fatalf("create auth provider failed: %v", err)
	}

	a := New(WithLionClient(db))
	enforce, providerID, err := a.getLocalMFAPolicy(ctx, db)
	if err != nil {
		t.Fatalf("getLocalMFAPolicy failed: %v", err)
	}
	if enforce {
		t.Fatalf("expected legacy provider config to be ignored after removing old field")
	}
	if providerID != provider.ID {
		t.Fatalf("unexpected provider id: got=%d want=%d", providerID, provider.ID)
	}
}

func TestGetGlobalSettingsReturnsSecurityCategory(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:get-global-settings-rpc?mode=memory&cache=shared&_fk=1")
	defer db.Close()

	a := New(WithLionClient(db), WithAESKey([]byte("0123456789abcdef0123456789abcdef")))
	if _, err := a.CreateDatabaseInitialize(ctx, &adminv1.CreateDatabaseInitializeRequest{}); err != nil {
		t.Fatalf("CreateDatabaseInitialize failed: %v", err)
	}

	resp, err := a.GetGlobalSettings(ctx, &adminv1.GetGlobalSettingsRequest{Category: globalSettingsCategorySecurity})
	if err != nil {
		t.Fatalf("GetGlobalSettings failed: %v", err)
	}
	if resp.GetCategory() != globalSettingsCategorySecurity {
		t.Fatalf("unexpected category: got=%q want=%q", resp.GetCategory(), globalSettingsCategorySecurity)
	}
	if len(resp.GetSettings()) != 6 {
		t.Fatalf("unexpected settings length: got=%d want=%d", len(resp.GetSettings()), 6)
	}
}

func TestListGlobalSettingsReturnsRegisteredCategories(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:list-global-settings-rpc?mode=memory&cache=shared&_fk=1")
	defer db.Close()

	a := New(WithLionClient(db), WithAESKey([]byte("0123456789abcdef0123456789abcdef")))
	if _, err := a.CreateDatabaseInitialize(ctx, &adminv1.CreateDatabaseInitializeRequest{}); err != nil {
		t.Fatalf("CreateDatabaseInitialize failed: %v", err)
	}

	resp, err := a.ListGlobalSettings(ctx, &adminv1.ListGlobalSettingsRequest{})
	if err != nil {
		t.Fatalf("ListGlobalSettings failed: %v", err)
	}
	if len(resp.GetCategories()) != 1 {
		t.Fatalf("unexpected category count: got=%d want=%d", len(resp.GetCategories()), 1)
	}
	if resp.GetCategories()[0].GetCategory() != globalSettingsCategorySecurity {
		t.Fatalf("unexpected category: got=%q want=%q", resp.GetCategories()[0].GetCategory(), globalSettingsCategorySecurity)
	}
}

func TestUpdateGlobalSettingsRejectsUnknownKeyAndRollsBack(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:update-global-settings-rollback?mode=memory&cache=shared&_fk=1")
	defer db.Close()

	a := New(WithLionClient(db), WithAESKey([]byte("0123456789abcdef0123456789abcdef")))
	if _, err := a.CreateDatabaseInitialize(ctx, &adminv1.CreateDatabaseInitializeRequest{}); err != nil {
		t.Fatalf("CreateDatabaseInitialize failed: %v", err)
	}

	_, err := a.UpdateGlobalSettings(ctx, &adminv1.UpdateGlobalSettingsRequest{
		Category: globalSettingsCategorySecurity,
		Updates: []*adminv1.UpdateGlobalSetting{
			{SettingKey: globalSettingKeyMFAMaxVerifyAttempts, SettingValue: "9"},
			{SettingKey: "mfa.unknown_key", SettingValue: "1"},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unexpected error code: got=%s want=%s err=%v", status.Code(err), codes.InvalidArgument, err)
	}

	row, queryErr := db.GlobalSettings.Query().
		Where(
			globalsettings.CategoryEQ(globalSettingsCategorySecurity),
			globalsettings.SettingKeyEQ(globalSettingKeyMFAMaxVerifyAttempts),
		).
		Only(ctx)
	if queryErr != nil {
		t.Fatalf("query global setting failed: %v", queryErr)
	}
	if row.SettingValue != "5" {
		t.Fatalf("expected transaction rollback to preserve old value, got=%q", row.SettingValue)
	}
}

func TestUpdateGlobalSettingsPersistsValidatedValues(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:update-global-settings-success?mode=memory&cache=shared&_fk=1")
	defer db.Close()

	a := New(WithLionClient(db), WithAESKey([]byte("0123456789abcdef0123456789abcdef")))
	if _, err := a.CreateDatabaseInitialize(ctx, &adminv1.CreateDatabaseInitializeRequest{}); err != nil {
		t.Fatalf("CreateDatabaseInitialize failed: %v", err)
	}

	resp, err := a.UpdateGlobalSettings(ctx, &adminv1.UpdateGlobalSettingsRequest{
		Category: globalSettingsCategorySecurity,
		Updates: []*adminv1.UpdateGlobalSetting{
			{SettingKey: globalSettingKeyMFAMaxVerifyAttempts, SettingValue: "9"},
			{SettingKey: globalSettingKeyMFATOTPIssuer, SettingValue: "Acme Admin"},
		},
	})
	if err != nil {
		t.Fatalf("UpdateGlobalSettings failed: %v", err)
	}
	if resp.GetCategory() == nil || resp.GetCategory().GetCategory() != globalSettingsCategorySecurity {
		t.Fatalf("unexpected response category: %+v", resp.GetCategory())
	}

	row, queryErr := db.GlobalSettings.Query().
		Where(
			globalsettings.CategoryEQ(globalSettingsCategorySecurity),
			globalsettings.SettingKeyEQ(globalSettingKeyMFAMaxVerifyAttempts),
		).
		Only(ctx)
	if queryErr != nil {
		t.Fatalf("query max verify attempts failed: %v", queryErr)
	}
	if row.SettingValue != "9" {
		t.Fatalf("unexpected updated value: got=%q want=%q", row.SettingValue, "9")
	}
}

func TestUpdateGlobalSettingsRejectsOutOfRangeValue(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:update-global-settings-range?mode=memory&cache=shared&_fk=1")
	defer db.Close()

	a := New(WithLionClient(db), WithAESKey([]byte("0123456789abcdef0123456789abcdef")))
	if _, err := a.CreateDatabaseInitialize(ctx, &adminv1.CreateDatabaseInitializeRequest{}); err != nil {
		t.Fatalf("CreateDatabaseInitialize failed: %v", err)
	}

	_, err := a.UpdateGlobalSettings(ctx, &adminv1.UpdateGlobalSettingsRequest{
		Category: globalSettingsCategorySecurity,
		Updates: []*adminv1.UpdateGlobalSetting{
			{SettingKey: globalSettingKeyMFAMaxVerifyAttempts, SettingValue: "21"},
		},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unexpected error code: got=%s want=%s err=%v", status.Code(err), codes.InvalidArgument, err)
	}
}

func TestKnownAdminAPIGlobalSettingHelpersUseDefaults(t *testing.T) {
	a := New()
	ctx := context.Background()

	if got := a.getLoginAccessTokenTTL(ctx); got != 24*time.Hour {
		t.Fatalf("unexpected login access token ttl: got=%s want=%s", got, 24*time.Hour)
	}
	if got := a.getMFAChallengeTTL(ctx); got != 5*time.Minute {
		t.Fatalf("unexpected mfa challenge ttl: got=%s want=%s", got, 5*time.Minute)
	}
	if got := a.getMFAMaxVerifyAttempts(ctx); got != 5 {
		t.Fatalf("unexpected mfa max verify attempts: got=%d want=%d", got, 5)
	}
	if got := a.getMFARecoveryCodesCount(ctx); got != 8 {
		t.Fatalf("unexpected mfa recovery codes count: got=%d want=%d", got, 8)
	}
	if got := a.getMFATOTPIssuer(ctx); got != "KnownAdmin" {
		t.Fatalf("unexpected mfa totp issuer: got=%q want=%q", got, "KnownAdmin")
	}
}

func TestKnownAdminAPIGlobalSettingHelpersUseDBOverrides(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:global-settings-helper-overrides?mode=memory&cache=shared&_fk=1")
	defer db.Close()

	createSetting := func(key, value string, valueType globalSettingValueType) {
		t.Helper()
		_, err := db.GlobalSettings.Create().
			SetCategory(globalSettingsCategorySecurity).
			SetSettingKey(key).
			SetSettingValue(value).
			SetValueType(string(valueType)).
			SetProtected(true).
			Save(ctx)
		if err != nil {
			t.Fatalf("create global setting %s failed: %v", key, err)
		}
	}

	createSetting(globalSettingKeyLoginAccessTokenTTL, "36h", globalSettingValueTypeDuration)
	createSetting(globalSettingKeyMFAChallengeTTL, "10m", globalSettingValueTypeDuration)
	createSetting(globalSettingKeyMFAMaxVerifyAttempts, "9", globalSettingValueTypeInt)
	createSetting(globalSettingKeyMFARecoveryCodesCount, "10", globalSettingValueTypeInt)
	createSetting(globalSettingKeyMFATOTPIssuer, "AcmeAdmin", globalSettingValueTypeString)

	a := New(WithLionClient(db))

	if got := a.getLoginAccessTokenTTL(ctx); got != 36*time.Hour {
		t.Fatalf("unexpected login access token ttl override: got=%s want=%s", got, 36*time.Hour)
	}
	if got := a.getMFAChallengeTTL(ctx); got != 10*time.Minute {
		t.Fatalf("unexpected mfa challenge ttl override: got=%s want=%s", got, 10*time.Minute)
	}
	if got := a.getMFAMaxVerifyAttempts(ctx); got != 9 {
		t.Fatalf("unexpected mfa max verify attempts override: got=%d want=%d", got, 9)
	}
	if got := a.getMFARecoveryCodesCount(ctx); got != 10 {
		t.Fatalf("unexpected mfa recovery codes count override: got=%d want=%d", got, 10)
	}
	if got := a.getMFATOTPIssuer(ctx); got != "AcmeAdmin" {
		t.Fatalf("unexpected mfa totp issuer override: got=%q want=%q", got, "AcmeAdmin")
	}
}

func TestCreateDatabaseInitializeSeedsGlobalSettingsIdempotently(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:global-settings-seeds?mode=memory&cache=shared&_fk=1")
	defer db.Close()

	a := New(WithLionClient(db), WithAESKey([]byte("0123456789abcdef0123456789abcdef")))
	if _, err := a.CreateDatabaseInitialize(ctx, &adminv1.CreateDatabaseInitializeRequest{}); err != nil {
		t.Fatalf("CreateDatabaseInitialize first run failed: %v", err)
	}

	count, err := db.GlobalSettings.Query().Count(ctx)
	if err != nil {
		t.Fatalf("count global settings failed: %v", err)
	}
	if count != 6 {
		t.Fatalf("unexpected seeded global settings count: got=%d want=%d", count, 6)
	}

	_, err = db.GlobalSettings.Update().
		Where(
			globalsettings.CategoryEQ(globalSettingsCategorySecurity),
			globalsettings.SettingKeyEQ(globalSettingKeyLoginAccessTokenTTL),
		).
		SetSettingValue("48h").
		Save(ctx)
	if err != nil {
		t.Fatalf("update seeded global setting failed: %v", err)
	}

	if _, err := a.CreateDatabaseInitialize(ctx, &adminv1.CreateDatabaseInitializeRequest{}); err != nil {
		t.Fatalf("CreateDatabaseInitialize second run failed: %v", err)
	}

	count, err = db.GlobalSettings.Query().Count(ctx)
	if err != nil {
		t.Fatalf("count global settings after rerun failed: %v", err)
	}
	if count != 6 {
		t.Fatalf("unexpected global settings count after rerun: got=%d want=%d", count, 6)
	}

	row, err := db.GlobalSettings.Query().
		Where(
			globalsettings.CategoryEQ(globalSettingsCategorySecurity),
			globalsettings.SettingKeyEQ(globalSettingKeyLoginAccessTokenTTL),
		).
		Only(ctx)
	if err != nil {
		t.Fatalf("query seeded global setting failed: %v", err)
	}
	if row.SettingValue != "48h" {
		t.Fatalf("expected rerun seed to preserve existing setting value, got=%q", row.SettingValue)
	}
}

func TestCreateAuthTokenUsesGlobalSettingDefaultTTL(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:create-auth-token-global-ttl?mode=memory&cache=shared&_fk=1")
	defer db.Close()

	_, err := db.GlobalSettings.Create().
		SetCategory(globalSettingsCategorySecurity).
		SetSettingKey(globalSettingKeyLoginAccessTokenTTL).
		SetSettingValue("36h").
		SetValueType(string(globalSettingValueTypeDuration)).
		SetProtected(true).
		Save(ctx)
	if err != nil {
		t.Fatalf("create global setting failed: %v", err)
	}

	passwordHash := "sha256-password"
	staticUsers := StaticUsers{
		&StaticUser{Username: "alice", PasswordHash: passwordHash},
	}
	a := New(WithLionClient(db), WithStaticUsers(&staticUsers))

	resp, err := a.CreateAuthToken(ctx, &adminv1.CreateAuthTokenRequest{
		Appid:        "web",
		Username:     "alice",
		PasswordHash: passwordHash,
	})
	if err != nil {
		t.Fatalf("CreateAuthToken failed: %v", err)
	}
	if resp.ExpiresIn != int32((36 * time.Hour) / time.Second) {
		t.Fatalf("unexpected expires_in: got=%d want=%d", resp.ExpiresIn, int32((36*time.Hour)/time.Second))
	}
}

func TestSocialUsersIssueAccessTokenForUserUsesConfiguredTTL(t *testing.T) {
	ctx := context.Background()
	db := enttest.Open(t, "sqlite3", "file:social-users-global-ttl?mode=memory&cache=shared&_fk=1")
	defer db.Close()

	_, err := db.GlobalSettings.Create().
		SetCategory(globalSettingsCategorySecurity).
		SetSettingKey(globalSettingKeyLoginAccessTokenTTL).
		SetSettingValue("36h").
		SetValueType(string(globalSettingValueTypeDuration)).
		SetProtected(true).
		Save(ctx)
	if err != nil {
		t.Fatalf("create global setting failed: %v", err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key failed: %v", err)
	}

	_, err = db.Users.Create().
		SetUsername("alice").
		SetNickname("Alice").
		SetUserStatus(int(adminv1.User_ACTIVE.Number())).
		Save(ctx)
	if err != nil {
		t.Fatalf("create user failed: %v", err)
	}

	s := &socialUsers{
		db:         db,
		privateKey: privateKey,
	}
	token, _, err := s.issueAccessTokenForUser(ctx, &lion.Users{ID: 1, Username: "alice", Nickname: "Alice"})
	if err != nil {
		t.Fatalf("issueAccessTokenForUser failed: %v", err)
	}

	claims := &auth.IDTokenClaims{}
	parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse issued token failed: %v", err)
	}
	if !parsedToken.Valid {
		t.Fatalf("expected issued token to be valid")
	}
	if claims.ExpiresAt == nil {
		t.Fatalf("expected expires_at claim")
	}

	remaining := time.Until(claims.ExpiresAt.Time)
	if remaining < 35*time.Hour || remaining > 36*time.Hour+time.Minute {
		t.Fatalf("unexpected token ttl window: remaining=%s", remaining)
	}
}