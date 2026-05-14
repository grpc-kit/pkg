package admin

import (
	"context"
	"fmt"
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
	raw, spec, found, err := r.getRawValue(ctx, category, settingKey)
	if err != nil {
		return false, false, err
	}
	parsed, parseErr := strconv.ParseBool(raw)
	if parseErr == nil {
		return parsed, found, nil
	}
	r.warnParseFallback(category, settingKey, raw, spec.DefaultValue, parseErr)
	parsed, _ = strconv.ParseBool(spec.DefaultValue)
	return parsed, false, nil
}

func (r *globalSettingsReader) GetInt(ctx context.Context, category, settingKey string) (int, bool, error) {
	raw, spec, found, err := r.getRawValue(ctx, category, settingKey)
	if err != nil {
		return 0, false, err
	}
	parsed, parseErr := strconv.Atoi(raw)
	if parseErr == nil {
		return parsed, found, nil
	}
	r.warnParseFallback(category, settingKey, raw, spec.DefaultValue, parseErr)
	parsed, _ = strconv.Atoi(spec.DefaultValue)
	return parsed, false, nil
}

func (r *globalSettingsReader) GetDuration(ctx context.Context, category, settingKey string) (time.Duration, bool, error) {
	raw, spec, found, err := r.getRawValue(ctx, category, settingKey)
	if err != nil {
		return 0, false, err
	}
	parsed, parseErr := time.ParseDuration(raw)
	if parseErr == nil {
		return parsed, found, nil
	}
	r.warnParseFallback(category, settingKey, raw, spec.DefaultValue, parseErr)
	parsed, _ = time.ParseDuration(spec.DefaultValue)
	return parsed, false, nil
}

func (r *globalSettingsReader) GetString(ctx context.Context, category, settingKey string) (string, bool, error) {
	raw, _, found, err := r.getRawValue(ctx, category, settingKey)
	if err != nil {
		return "", false, err
	}
	return raw, found, nil
}

func (r *globalSettingsReader) getRawValue(ctx context.Context, category, settingKey string) (string, globalSettingSpec, bool, error) {
	spec, ok := lookupGlobalSettingSpec(category, settingKey)
	if !ok {
		return "", globalSettingSpec{}, false, fmt.Errorf("unknown global setting: %s/%s", category, settingKey)
	}
	if r == nil || r.db == nil {
		return spec.DefaultValue, spec, false, nil
	}
	row, err := r.db.GlobalSettings.Query().
		Where(
			globalsettings.CategoryEQ(category),
			globalsettings.SettingKeyEQ(settingKey),
		).
		Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return spec.DefaultValue, spec, false, nil
		}
		return "", globalSettingSpec{}, false, err
	}
	return row.SettingValue, spec, true, nil
}

func (r *globalSettingsReader) warnParseFallback(category, settingKey, raw, fallback string, parseErr error) {
	if r == nil || r.logger == nil {
		return
	}
	r.logger.Warnf(
		"global setting parse fallback: category=%s setting_key=%s raw=%q fallback=%q err=%v",
		category,
		settingKey,
		raw,
		fallback,
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