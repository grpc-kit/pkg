package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/globalsettings"
	"github.com/sirupsen/logrus"
)

type globalSettingsReader struct {
	db     *lion.Client
	logger *logrus.Entry
}

func newGlobalSettingsReader(logger *logrus.Entry, db *lion.Client) *globalSettingsReader {
	return &globalSettingsReader{db: db, logger: logger}
}

func (r *globalSettingsReader) GetBool(ctx context.Context, category, settingKey string) (bool, bool, error) {
	raw, spec, found, builtIn, err := r.getRawValue(ctx, category, settingKey)
	if err != nil {
		return false, false, err
	}
	if spec.ValueType != globalSettingValueTypeBool {
		return false, false, globalSettingTypeMismatch(category, settingKey, globalSettingValueTypeBool, spec.ValueType)
	}
	parsed, parseErr := strconv.ParseBool(raw)
	if parseErr == nil {
		return parsed, found, nil
	}
	if !builtIn {
		return false, false, fmt.Errorf("invalid stored global setting: %s/%s", category, settingKey)
	}
	r.warnParseFallback(category, settingKey, parseErr)
	parsed, _ = strconv.ParseBool(spec.DefaultValue)
	return parsed, false, nil
}

func (r *globalSettingsReader) GetInt(ctx context.Context, category, settingKey string) (int, bool, error) {
	raw, spec, found, builtIn, err := r.getRawValue(ctx, category, settingKey)
	if err != nil {
		return 0, false, err
	}
	if spec.ValueType != globalSettingValueTypeInt {
		return 0, false, globalSettingTypeMismatch(category, settingKey, globalSettingValueTypeInt, spec.ValueType)
	}
	parsed, parseErr := strconv.Atoi(raw)
	if parseErr == nil {
		return parsed, found, nil
	}
	if !builtIn {
		return 0, false, fmt.Errorf("invalid stored global setting: %s/%s", category, settingKey)
	}
	r.warnParseFallback(category, settingKey, parseErr)
	parsed, _ = strconv.Atoi(spec.DefaultValue)
	return parsed, false, nil
}

func (r *globalSettingsReader) GetFloat(ctx context.Context, category, settingKey string) (float64, bool, error) {
	raw, spec, found, builtIn, err := r.getRawValue(ctx, category, settingKey)
	if err != nil {
		return 0, false, err
	}
	if spec.ValueType != globalSettingValueTypeFloat {
		return 0, false, globalSettingTypeMismatch(category, settingKey, globalSettingValueTypeFloat, spec.ValueType)
	}
	parsed, parseErr := strconv.ParseFloat(raw, 64)
	if parseErr == nil && !math.IsInf(parsed, 0) && !math.IsNaN(parsed) {
		return parsed, found, nil
	}
	if !builtIn {
		return 0, false, fmt.Errorf("invalid stored global setting: %s/%s", category, settingKey)
	}
	r.warnParseFallback(category, settingKey, parseErr)
	parsed, _ = strconv.ParseFloat(spec.DefaultValue, 64)
	return parsed, false, nil
}

func (r *globalSettingsReader) GetDuration(ctx context.Context, category, settingKey string) (time.Duration, bool, error) {
	raw, spec, found, builtIn, err := r.getRawValue(ctx, category, settingKey)
	if err != nil {
		return 0, false, err
	}
	if spec.ValueType != globalSettingValueTypeDuration {
		return 0, false, globalSettingTypeMismatch(category, settingKey, globalSettingValueTypeDuration, spec.ValueType)
	}
	parsed, parseErr := time.ParseDuration(raw)
	if parseErr == nil {
		return parsed, found, nil
	}
	if !builtIn {
		return 0, false, fmt.Errorf("invalid stored global setting: %s/%s", category, settingKey)
	}
	r.warnParseFallback(category, settingKey, parseErr)
	parsed, _ = time.ParseDuration(spec.DefaultValue)
	return parsed, false, nil
}

func (r *globalSettingsReader) GetString(ctx context.Context, category, settingKey string) (string, bool, error) {
	raw, spec, found, _, err := r.getRawValue(ctx, category, settingKey)
	if err != nil {
		return "", false, err
	}
	if spec.ValueType != globalSettingValueTypeString {
		return "", false, globalSettingTypeMismatch(category, settingKey, globalSettingValueTypeString, spec.ValueType)
	}
	return raw, found, nil
}

func (r *globalSettingsReader) GetStringArray(ctx context.Context, category, settingKey string) ([]string, bool, error) {
	raw, spec, found, _, err := r.getRawValue(ctx, category, settingKey)
	if err != nil {
		return nil, false, err
	}
	if spec.ValueType != globalSettingValueTypeStringArray {
		return nil, false, globalSettingTypeMismatch(category, settingKey, globalSettingValueTypeStringArray, spec.ValueType)
	}
	var result []string
	if err := json.Unmarshal([]byte(raw), &result); err != nil || result == nil {
		return nil, false, fmt.Errorf("invalid stored global setting: %s/%s", category, settingKey)
	}
	return result, found, nil
}

func (r *globalSettingsReader) GetJSON(ctx context.Context, category, settingKey string) (json.RawMessage, bool, error) {
	raw, spec, found, _, err := r.getRawValue(ctx, category, settingKey)
	if err != nil {
		return nil, false, err
	}
	if spec.ValueType != globalSettingValueTypeJSON {
		return nil, false, globalSettingTypeMismatch(category, settingKey, globalSettingValueTypeJSON, spec.ValueType)
	}
	var decoded any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return nil, false, fmt.Errorf("invalid stored global setting: %s/%s", category, settingKey)
	}
	return json.RawMessage(raw), found, nil
}

func (r *globalSettingsReader) getRawValue(ctx context.Context, category, settingKey string) (string, globalSettingSpec, bool, bool, error) {
	if !isGlobalSettingsCategory(category) {
		return "", globalSettingSpec{}, false, false, fmt.Errorf("unknown global setting category: %s", category)
	}
	spec, builtIn := lookupGlobalSettingSpec(category, settingKey)
	if r == nil || r.db == nil {
		if builtIn {
			return spec.DefaultValue, spec, false, true, nil
		}
		return "", globalSettingSpec{}, false, false, fmt.Errorf("unknown global setting: %s/%s", category, settingKey)
	}
	row, err := r.db.GlobalSettings.Query().
		Where(
			globalsettings.CategoryEQ(category),
			globalsettings.SettingKeyEQ(settingKey),
		).
		Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) && builtIn {
			return spec.DefaultValue, spec, false, true, nil
		}
		if lion.IsNotFound(err) {
			return "", globalSettingSpec{}, false, false, fmt.Errorf("unknown global setting: %s/%s", category, settingKey)
		}
		return "", globalSettingSpec{}, false, builtIn, err
	}
	if builtIn {
		return row.SettingValue, spec, true, true, nil
	}
	return row.SettingValue, globalSettingSpec{ValueType: globalSettingValueType(row.ValueType)}, true, false, nil
}

func globalSettingTypeMismatch(category, settingKey string, expected, actual globalSettingValueType) error {
	return fmt.Errorf("global setting type mismatch for %s/%s: expected %s, got %s", category, settingKey, expected, actual)
}

func (r *globalSettingsReader) warnParseFallback(category, settingKey string, parseErr error) {
	if r == nil || r.logger == nil {
		return
	}
	r.logger.Warnf(
		"global setting parse fallback: category=%s setting_key=%s err=%v",
		category,
		settingKey,
		parseErr,
	)
}

func (a *KnownAdminAPI) globalSettingsReader() *globalSettingsReader {
	if a == nil {
		return newGlobalSettingsReader(nil, nil)
	}
	return newGlobalSettingsReader(a.logger, a.config.db)
}

func loginAccessTokenTTLFrom(logger *logrus.Entry, db *lion.Client) time.Duration {
	ttl, _, err := newGlobalSettingsReader(logger, db).GetDuration(context.Background(), globalSettingsCategorySecurity, globalSettingKeyLoginAccessTokenTTL)
	if err != nil {
		if logger != nil {
			logger.Warnf("failed to read %s/%s: %v", globalSettingsCategorySecurity, globalSettingKeyLoginAccessTokenTTL, err)
		}
		return 24 * time.Hour
	}
	return ttl
}

func (a *KnownAdminAPI) getLoginAccessTokenTTL(ctx context.Context) time.Duration {
	return loginAccessTokenTTLFrom(a.logger, a.config.db)
}

func (a *KnownAdminAPI) getMFAChallengeTTL(ctx context.Context) time.Duration {
	ttl, _, err := a.globalSettingsReader().GetDuration(ctx, globalSettingsCategorySecurity, globalSettingKeyMFAChallengeTTL)
	if err != nil {
		if a != nil && a.logger != nil {
			a.logger.Warnf("failed to read %s/%s: %v", globalSettingsCategorySecurity, globalSettingKeyMFAChallengeTTL, err)
		}
		return 5 * time.Minute
	}
	return ttl
}

func (a *KnownAdminAPI) getMFAMaxVerifyAttempts(ctx context.Context) int {
	value, _, err := a.globalSettingsReader().GetInt(ctx, globalSettingsCategorySecurity, globalSettingKeyMFAMaxVerifyAttempts)
	if err != nil {
		if a != nil && a.logger != nil {
			a.logger.Warnf("failed to read %s/%s: %v", globalSettingsCategorySecurity, globalSettingKeyMFAMaxVerifyAttempts, err)
		}
		return 5
	}
	return value
}

func (a *KnownAdminAPI) getMFARecoveryCodesCount(ctx context.Context) int {
	value, _, err := a.globalSettingsReader().GetInt(ctx, globalSettingsCategorySecurity, globalSettingKeyMFARecoveryCodesCount)
	if err != nil {
		if a != nil && a.logger != nil {
			a.logger.Warnf("failed to read %s/%s: %v", globalSettingsCategorySecurity, globalSettingKeyMFARecoveryCodesCount, err)
		}
		return 8
	}
	return value
}

func (a *KnownAdminAPI) getMFATOTPIssuer(ctx context.Context) string {
	value, _, err := a.globalSettingsReader().GetString(ctx, globalSettingsCategorySecurity, globalSettingKeyMFATOTPIssuer)
	if err != nil {
		if a != nil && a.logger != nil {
			a.logger.Warnf("failed to read %s/%s: %v", globalSettingsCategorySecurity, globalSettingKeyMFATOTPIssuer, err)
		}
		return "KnownAdmin"
	}
	return value
}

func durationSecondsInt32(value time.Duration) int32 {
	return int32(value / time.Second)
}

func durationSecondsInt64(value time.Duration) int64 {
	return int64(value / time.Second)
}
