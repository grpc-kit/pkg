package admin

import (
	"context"
	"errors"
	"fmt"
	"slices"

	mysqlDriver "github.com/go-sql-driver/mysql"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/globalsettings"
	"github.com/lib/pq"
)

type usernameStrategy string

const (
	usernameExternalThenPrefixed usernameStrategy = "external_then_prefixed"
	usernameExternalStrict       usernameStrategy = "external_strict"
	usernameProviderPrefixed     usernameStrategy = "provider_prefixed"
	identityTransactionAttempts                   = 3
)

var errInvalidIdentityPolicy = errors.New("invalid identity policy")

var identitySettingKeys = []string{
	globalSettingKeyIdentityUsernameStrategy,
	globalSettingKeyIdentityAutoLinkByUsername,
	globalSettingKeyIdentityAutoLinkByVerifiedContact,
}

type identityPolicy struct {
	UsernameStrategy usernameStrategy
	LinkByUsername   bool
	LinkByContact    bool
}

func defaultIdentityPolicy() identityPolicy {
	return identityPolicy{
		UsernameStrategy: usernameExternalThenPrefixed,
		LinkByContact:    true,
	}
}

func (p identityPolicy) validate() error {
	switch p.UsernameStrategy {
	case usernameExternalThenPrefixed, usernameExternalStrict:
	case usernameProviderPrefixed:
		if p.LinkByUsername {
			return fmt.Errorf("%w: provider_prefixed cannot be combined with username auto-link", errInvalidIdentityPolicy)
		}
	default:
		return fmt.Errorf("%w: unknown username strategy", errInvalidIdentityPolicy)
	}
	return nil
}

// readIdentityPolicy reads the complete policy in one query. Unlike the generic
// settings reader, malformed persisted security settings never fall back.
func readIdentityPolicy(ctx context.Context, query *lion.GlobalSettingsQuery) (identityPolicy, error) {
	if query == nil {
		return defaultIdentityPolicy(), nil
	}
	rows, err := query.Where(
		globalsettings.CategoryEQ(globalSettingsCategorySecurity),
		globalsettings.SettingKeyIn(identitySettingKeys...),
	).All(ctx)
	if err != nil {
		return identityPolicy{}, fmt.Errorf("read identity policy: %w", err)
	}
	return identityPolicyFromRows(rows)
}

func identityPolicyFromRows(rows []*lion.GlobalSettings) (identityPolicy, error) {
	policy := defaultIdentityPolicy()
	for _, row := range rows {
		if !slices.Contains(identitySettingKeys, row.SettingKey) {
			continue
		}
		spec, _ := lookupGlobalSettingSpec(globalSettingsCategorySecurity, row.SettingKey)
		if row.ValueType != string(spec.ValueType) {
			return identityPolicy{}, fmt.Errorf("%w: setting type for %s", errInvalidIdentityPolicy, row.SettingKey)
		}
		switch row.SettingKey {
		case globalSettingKeyIdentityUsernameStrategy:
			policy.UsernameStrategy = usernameStrategy(row.SettingValue)
		case globalSettingKeyIdentityAutoLinkByUsername, globalSettingKeyIdentityAutoLinkByVerifiedContact:
			if row.SettingValue != "true" && row.SettingValue != "false" {
				return identityPolicy{}, fmt.Errorf("%w: setting value for %s", errInvalidIdentityPolicy, row.SettingKey)
			}
			if row.SettingKey == globalSettingKeyIdentityAutoLinkByUsername {
				policy.LinkByUsername = row.SettingValue == "true"
			} else {
				policy.LinkByContact = row.SettingValue == "true"
			}
		}
	}
	if err := policy.validate(); err != nil {
		return identityPolicy{}, err
	}
	return policy, nil
}

func retryableDatabaseError(err error) bool {
	// The repository's pq version predates SQLState(); inspect its typed code.
	var postgresErr *pq.Error
	if errors.As(err, &postgresErr) && (postgresErr.Code == "40001" || postgresErr.Code == "40P01") {
		return true
	}
	var state interface{ SQLState() string }
	if errors.As(err, &state) {
		switch state.SQLState() {
		case "40001", "40P01": // serialization failure / deadlock
			return true
		}
	}
	var mysqlErr *mysqlDriver.MySQLError
	return errors.As(err, &mysqlErr) && (mysqlErr.Number == 1213 || mysqlErr.Number == 1205)
}
