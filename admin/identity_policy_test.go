package admin

import (
	"errors"
	"fmt"
	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/lion"
	"github.com/lib/pq"
	"strings"
	"testing"
)

func TestIdentityPolicyStrictSnapshot(t *testing.T) {
	row := func(key, kind, value string) *lion.GlobalSettings {
		return &lion.GlobalSettings{SettingKey: key, ValueType: kind, SettingValue: value}
	}
	wantDefault := identityPolicy{UsernameStrategy: usernameExternalThenPrefixed, LinkByContact: true}
	cases := []struct {
		name    string
		rows    []*lion.GlobalSettings
		want    identityPolicy
		invalid bool
	}{
		{name: "defaults", want: wantDefault},
		{name: "explicit false", rows: []*lion.GlobalSettings{row(globalSettingKeyIdentityAutoLinkByVerifiedContact, "bool", "false")}, want: identityPolicy{UsernameStrategy: usernameExternalThenPrefixed}},
		{name: "username without contacts", rows: []*lion.GlobalSettings{row(globalSettingKeyIdentityAutoLinkByUsername, "bool", "true"), row(globalSettingKeyIdentityAutoLinkByVerifiedContact, "bool", "false")}, want: identityPolicy{UsernameStrategy: usernameExternalThenPrefixed, LinkByUsername: true}},
		{name: "strict", rows: []*lion.GlobalSettings{row(globalSettingKeyIdentityUsernameStrategy, "string", "external_strict")}, want: identityPolicy{UsernameStrategy: usernameExternalStrict, LinkByContact: true}},
		{name: "legacy key inert", rows: []*lion.GlobalSettings{row("identity.auto_link", "bool", "false")}, want: wantDefault},
		{name: "unknown strategy", rows: []*lion.GlobalSettings{row(globalSettingKeyIdentityUsernameStrategy, "string", "other")}, invalid: true},
		{name: "invalid boolean", rows: []*lion.GlobalSettings{row(globalSettingKeyIdentityAutoLinkByUsername, "bool", "1")}, invalid: true},
		{name: "corrupted boolean", rows: []*lion.GlobalSettings{row(globalSettingKeyIdentityAutoLinkByVerifiedContact, "bool", "broken")}, invalid: true},
		{name: "wrong stored type", rows: []*lion.GlobalSettings{row(globalSettingKeyIdentityAutoLinkByUsername, "string", "false")}, invalid: true},
		{name: "illegal combination", rows: []*lion.GlobalSettings{row(globalSettingKeyIdentityUsernameStrategy, "string", "provider_prefixed"), row(globalSettingKeyIdentityAutoLinkByUsername, "bool", "true")}, invalid: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := identityPolicyFromRows(tc.rows)
			if tc.invalid {
				if err == nil {
					t.Fatal("accepted invalid policy")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("policy=%+v err=%v, want %+v", got, err, tc.want)
			}
		})
	}
}

func TestIdentityStrategyValidationAndRegistration(t *testing.T) {
	for _, tc := range []struct {
		key          string
		valueType    globalSettingValueType
		defaultValue string
	}{
		{globalSettingKeyIdentityUsernameStrategy, globalSettingValueTypeString, "external_then_prefixed"},
		{globalSettingKeyIdentityAutoLinkByUsername, globalSettingValueTypeBool, "false"},
		{globalSettingKeyIdentityAutoLinkByVerifiedContact, globalSettingValueTypeBool, "true"},
	} {
		spec, ok := lookupGlobalSettingSpec(globalSettingsCategorySecurity, tc.key)
		if !ok || !spec.Protected || spec.ValueType != tc.valueType || spec.DefaultValue != tc.defaultValue {
			t.Fatalf("setting %s spec: %+v", tc.key, spec)
		}
	}
	spec, _ := lookupGlobalSettingSpec(globalSettingsCategorySecurity, globalSettingKeyIdentityUsernameStrategy)
	for _, value := range []string{"external_then_prefixed", "external_strict", "provider_prefixed"} {
		if err := validateGlobalSettingValue(globalSettingKeyIdentityUsernameStrategy, value, spec); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"", "external", " external_strict", "EXTERNAL_STRICT"} {
		if err := validateGlobalSettingValue(globalSettingKeyIdentityUsernameStrategy, value, spec); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
	if _, found := lookupGlobalSettingSpec(globalSettingsCategorySecurity, "identity.auto_link"); found {
		t.Fatal("legacy setting is still registered")
	}
}

func TestUsernameEligibilityDoesNotPromoteDisplayNames(t *testing.T) {
	cases := []struct {
		name   string
		kind   adminv1.AuthProvider_Type
		field  string
		config *oauthConfigData
		value  any
		want   bool
	}{
		{name: "github login", kind: adminv1.AuthProvider_GITHUB, field: "login", value: "Alice.Li", want: true},
		{name: "default display name", kind: adminv1.AuthProvider_OAUTH2, field: "name", value: "Alice"},
		{name: "explicit display name", kind: adminv1.AuthProvider_OAUTH2, field: "name", config: &oauthConfigData{UserinfoNameField: "name"}, value: "Alice"},
		{name: "configured login", kind: adminv1.AuthProvider_OAUTH2, field: "login", config: &oauthConfigData{UserinfoNameField: "login"}, value: "Alice", want: true},
		{name: "google display name", kind: adminv1.AuthProvider_GOOGLE, field: "name", value: "Alice"},
		{name: "object masquerading as username", kind: adminv1.AuthProvider_OAUTH2, field: "uid", config: &oauthConfigData{UserinfoNameField: "uid"}, value: map[string]string{"uid": "alice"}},
		{name: "numeric field", kind: adminv1.AuthProvider_OAUTH2, field: "uid", config: &oauthConfigData{UserinfoNameField: "uid"}, value: 42},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := oauthUsernameIsUsable(int(tc.kind), tc.config, map[string]any{tc.field: tc.value}, tc.field)
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestExternalUsernameValidationPreservesIdentitySpelling(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		strategy usernameStrategy
		invalid  bool
	}{
		{name: "case and separators", value: "Alice.Li-1", strategy: usernameExternalThenPrefixed},
		{name: "subject only fallback", strategy: usernameExternalThenPrefixed},
		{name: "strict missing", strategy: usernameExternalStrict, invalid: true},
		{name: "whitespace", value: " Alice ", strategy: usernameExternalThenPrefixed, invalid: true},
		{name: "unicode", value: "用户名", strategy: usernameExternalThenPrefixed, invalid: true},
		{name: "invalid delimiter", value: "alice@example", strategy: usernameExternalThenPrefixed, invalid: true},
		{name: "max length", value: strings.Repeat("a", 255), strategy: usernameExternalThenPrefixed},
		{name: "too long", value: strings.Repeat("a", 256), strategy: usernameExternalThenPrefixed, invalid: true},
		{name: "legacy cleaning retained", value: "Alice Doe", strategy: usernameProviderPrefixed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateExternalUsername(externalProvisioningInput{Username: tc.value}, identityPolicy{UsernameStrategy: tc.strategy})
			if (err != nil) != tc.invalid {
				t.Fatalf("validation err=%v", err)
			}
		})
	}
}

func TestDatabaseRetryClassificationUsesDriverCodes(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{&pq.Error{Code: "40001"}, true},
		{fmt.Errorf("wrapped: %w", &pq.Error{Code: "40P01"}), true},
		{&pq.Error{Code: "23505"}, false},
		{&mysqlDriver.MySQLError{Number: 1213}, true},
		{fmt.Errorf("wrapped: %w", &mysqlDriver.MySQLError{Number: 1205}), true},
		{&mysqlDriver.MySQLError{Number: 1062}, false},
		{errors.New("non-database error"), false},
	}
	for _, tc := range cases {
		if got := retryableDatabaseError(tc.err); got != tc.want {
			t.Fatalf("%v: retry=%v, want %v", tc.err, got, tc.want)
		}
	}
}

func TestExplicitOIDCUsernameCannotBeTrimmedIntoAnExistingAccount(t *testing.T) {
	for _, raw := range []string{" Alice ", " ", "Alice\t"} {
		claims := &auth.IDTokenClaims{CommonClaims: auth.CommonClaims{PreferredUsername: raw, RegisteredClaims: jwt.RegisteredClaims{Subject: "stable"}}}
		profile := externalUserClaimsFromIDToken(claims)
		if profile.UsernameIsFallback || profile.RawUsername != raw {
			t.Fatalf("lost explicit source %q: %+v", raw, profile)
		}
		if err := validateExternalUsername(externalProvisioningInput{Username: profile.RawUsername}, defaultIdentityPolicy()); err == nil {
			t.Fatalf("accepted ambiguous username %q", raw)
		}
	}
}
