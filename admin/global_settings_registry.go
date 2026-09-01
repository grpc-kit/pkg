package admin

import "time"

type globalSettingValueType string

const (
	globalSettingValueTypeBool        globalSettingValueType = "bool"
	globalSettingValueTypeInt         globalSettingValueType = "int"
	globalSettingValueTypeFloat       globalSettingValueType = "float"
	globalSettingValueTypeDuration    globalSettingValueType = "duration"
	globalSettingValueTypeString      globalSettingValueType = "string"
	globalSettingValueTypeStringArray globalSettingValueType = "string_array"
	globalSettingValueTypeJSON        globalSettingValueType = "json"
)

const (
	globalSettingsCategoryServices    = "services"
	globalSettingsCategoryDiscover    = "discover"
	globalSettingsCategorySecurity    = "security"
	globalSettingsCategoryDatabase    = "database"
	globalSettingsCategoryCachebox    = "cachebox"
	globalSettingsCategoryDebugger    = "debugger"
	globalSettingsCategoryObjstore    = "objstore"
	globalSettingsCategoryFrontend    = "frontend"
	globalSettingsCategoryObservables = "observables"
	globalSettingsCategoryCloudevents = "cloudevents"
	globalSettingsCategoryAutomations = "automations"
	globalSettingsCategoryAIConnector = "aiconnector"
	globalSettingsCategoryIndependent = "independent"

	globalSettingKeyLoginEnforceMFA       = "login.enforce_mfa"
	globalSettingKeyLoginAccessTokenTTL   = "login.access_token_ttl"
	globalSettingKeyMFAChallengeTTL       = "mfa.challenge_ttl"
	globalSettingKeyMFAMaxVerifyAttempts  = "mfa.max_verify_attempts"
	globalSettingKeyMFARecoveryCodesCount = "mfa.recovery_codes_count"
	globalSettingKeyMFATOTPIssuer         = "mfa.totp_issuer"
	globalSettingKeyIdentityAutoLink      = "identity.auto_link"
)

var globalSettingsCategories = []string{
	globalSettingsCategoryServices,
	globalSettingsCategoryDiscover,
	globalSettingsCategorySecurity,
	globalSettingsCategoryDatabase,
	globalSettingsCategoryCachebox,
	globalSettingsCategoryDebugger,
	globalSettingsCategoryObjstore,
	globalSettingsCategoryFrontend,
	globalSettingsCategoryObservables,
	globalSettingsCategoryCloudevents,
	globalSettingsCategoryAutomations,
	globalSettingsCategoryAIConnector,
	globalSettingsCategoryIndependent,
}

var globalSettingsCategorySet = map[string]struct{}{
	globalSettingsCategoryServices:    {},
	globalSettingsCategoryDiscover:    {},
	globalSettingsCategorySecurity:    {},
	globalSettingsCategoryDatabase:    {},
	globalSettingsCategoryCachebox:    {},
	globalSettingsCategoryDebugger:    {},
	globalSettingsCategoryObjstore:    {},
	globalSettingsCategoryFrontend:    {},
	globalSettingsCategoryObservables: {},
	globalSettingsCategoryCloudevents: {},
	globalSettingsCategoryAutomations: {},
	globalSettingsCategoryAIConnector: {},
	globalSettingsCategoryIndependent: {},
}

type globalSettingSpec struct {
	ValueType    globalSettingValueType
	DefaultValue string
	Description  string
	Protected    bool
	MinInt       *int
	MaxInt       *int
	MinDuration  *time.Duration
	MaxDuration  *time.Duration
	MaxLen       int
}

var globalSettingRegistry = map[string]map[string]globalSettingSpec{
	globalSettingsCategorySecurity: {
		globalSettingKeyLoginEnforceMFA: {
			ValueType:    globalSettingValueTypeBool,
			DefaultValue: "false",
			Description:  "Require MFA for all users after primary authentication.",
			Protected:    true,
		},
		globalSettingKeyLoginAccessTokenTTL: {
			ValueType:    globalSettingValueTypeDuration,
			DefaultValue: "24h",
			Description:  "Access token TTL for login and MFA completion.",
			Protected:    true,
			MinDuration:  durationPtr(5 * time.Minute),
			MaxDuration:  durationPtr(720 * time.Hour),
		},
		globalSettingKeyMFAChallengeTTL: {
			ValueType:    globalSettingValueTypeDuration,
			DefaultValue: "5m",
			Description:  "TTL for MFA login/setup challenges.",
			Protected:    true,
			MinDuration:  durationPtr(1 * time.Minute),
			MaxDuration:  durationPtr(1 * time.Hour),
		},
		globalSettingKeyMFAMaxVerifyAttempts: {
			ValueType:    globalSettingValueTypeInt,
			DefaultValue: "5",
			Description:  "Maximum MFA verification attempts before challenge rejection.",
			Protected:    true,
			MinInt:       intPtr(1),
			MaxInt:       intPtr(20),
		},
		globalSettingKeyMFARecoveryCodesCount: {
			ValueType:    globalSettingValueTypeInt,
			DefaultValue: "8",
			Description:  "Number of recovery codes generated for MFA enrollment.",
			Protected:    true,
			MinInt:       intPtr(4),
			MaxInt:       intPtr(20),
		},
		globalSettingKeyMFATOTPIssuer: {
			ValueType:    globalSettingValueTypeString,
			DefaultValue: "KnownAdmin",
			Description:  "Issuer shown in generated TOTP credentials.",
			Protected:    true,
			MaxLen:       64,
		},
		globalSettingKeyIdentityAutoLink: {
			ValueType:    globalSettingValueTypeBool,
			DefaultValue: "true",
			Description:  "Automatically link external identities to existing users by verified email or phone number.",
			Protected:    true,
		},
	},
}

func lookupGlobalSettingSpec(category, settingKey string) (globalSettingSpec, bool) {
	categorySpecs, ok := globalSettingRegistry[category]
	if !ok {
		return globalSettingSpec{}, false
	}
	spec, ok := categorySpecs[settingKey]
	if !ok {
		return globalSettingSpec{}, false
	}
	return spec, true
}

func isGlobalSettingsCategory(category string) bool {
	_, ok := globalSettingsCategorySet[category]
	return ok
}

func isSupportedGlobalSettingValueType(valueType globalSettingValueType) bool {
	switch valueType {
	case globalSettingValueTypeBool,
		globalSettingValueTypeInt,
		globalSettingValueTypeFloat,
		globalSettingValueTypeDuration,
		globalSettingValueTypeString,
		globalSettingValueTypeStringArray,
		globalSettingValueTypeJSON:
		return true
	default:
		return false
	}
}

func intPtr(value int) *int {
	return &value
}

func durationPtr(value time.Duration) *time.Duration {
	return &value
}
