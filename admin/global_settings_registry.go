package admin

import "time"

type globalSettingValueType string

const (
	globalSettingValueTypeBool     globalSettingValueType = "bool"
	globalSettingValueTypeInt      globalSettingValueType = "int"
	globalSettingValueTypeFloat    globalSettingValueType = "float"
	globalSettingValueTypeString   globalSettingValueType = "string"
	globalSettingValueTypeDuration globalSettingValueType = "duration"
	globalSettingValueTypeJSON     globalSettingValueType = "json"
)

const (
	globalSettingsCategorySecurity = "security"

	globalSettingKeyLoginEnforceMFA       = "login.enforce_mfa"
	globalSettingKeyLoginAccessTokenTTL   = "login.access_token_ttl"
	globalSettingKeyMFAChallengeTTL       = "mfa.challenge_ttl"
	globalSettingKeyMFAMaxVerifyAttempts  = "mfa.max_verify_attempts"
	globalSettingKeyMFARecoveryCodesCount = "mfa.recovery_codes_count"
	globalSettingKeyMFATOTPIssuer         = "mfa.totp_issuer"
)

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

func intPtr(value int) *int {
	return &value
}

func durationPtr(value time.Duration) *time.Duration {
	return &value
}