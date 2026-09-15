package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/useridentities"
)

func prepareLDAPProviderConfigForCreate(ctx context.Context, provider *adminv1.AuthProvider) error {
	if provider == nil || provider.GetType() != adminv1.AuthProvider_LDAP {
		return nil
	}
	config := provider.GetLdapConfig()
	if config == nil {
		return errs.InvalidArgument(ctx).WithMessage("ldap_config is required for LDAP provider")
	}
	if err := prepareLDAPPhoneNumberConfig(ctx, config); err != nil {
		return err
	}

	if config.UserIdAttribute == nil {
		value := defaultLDAPUserIDAttribute
		config.UserIdAttribute = &value
		return nil
	}

	normalized, err := normalizeLDAPUserIDAttributeName(config.GetUserIdAttribute())
	if err != nil {
		return errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	config.UserIdAttribute = &normalized
	return nil
}

func prepareLDAPProviderConfigForUpdate(
	ctx context.Context,
	db *lion.Client,
	existing *lion.AuthProviders,
	requested *adminv1.AuthProvider,
) error {
	if existing == nil || existing.ProviderType != int(adminv1.AuthProvider_LDAP.Number()) || requested == nil || requested.GetConfig() == nil {
		return nil
	}

	config := requested.GetLdapConfig()
	if config == nil {
		return errs.InvalidArgument(ctx).WithMessage("ldap_config is required when updating an LDAP provider configuration")
	}
	if err := prepareLDAPPhoneNumberConfig(ctx, config); err != nil {
		return err
	}

	var stored ldapConfigData
	if len(existing.Config) > 0 {
		if err := json.Unmarshal(existing.Config, &stored); err != nil {
			return errs.FailedPrecondition(ctx).WithMessage("stored LDAP provider configuration is invalid")
		}
	}

	if config.UserIdAttribute == nil {
		if stored.UserIDAttribute != nil {
			value := *stored.UserIDAttribute
			config.UserIdAttribute = &value
		}
		return nil
	}

	normalizedRequested, err := normalizeLDAPUserIDAttributeName(config.GetUserIdAttribute())
	if err != nil {
		return errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	config.UserIdAttribute = &normalizedRequested

	storedAttribute := effectiveLDAPUserIDAttribute(&stored)
	normalizedStored, err := normalizeLDAPUserIDAttributeName(storedAttribute)
	if err != nil {
		return errs.FailedPrecondition(ctx).WithMessage("stored LDAP user_id_attribute is invalid")
	}
	if strings.EqualFold(normalizedStored, normalizedRequested) {
		return nil
	}

	identityCount, err := db.UserIdentities.Query().
		Where(useridentities.ProviderIDEQ(existing.ID)).
		Count(ctx)
	if err != nil {
		return fmt.Errorf("count LDAP provider identities: %w", err)
	}
	if identityCount > 0 {
		return errs.FailedPrecondition(ctx).WithMessage(
			"LDAP user_id_attribute cannot be changed while identities exist; run a controlled identity migration first",
		)
	}
	return nil
}

func prepareLDAPPhoneNumberConfig(ctx context.Context, config *adminv1.LdapConfig) error {
	attribute, err := normalizeLDAPPhoneNumberAttributeName(config.GetPhoneNumberAttribute())
	if err != nil {
		return errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	config.PhoneNumberAttribute = attribute
	if attribute == "" {
		config.PhoneNumberDefaultRegion = ""
		return nil
	}

	region, err := normalizePhoneNumberDefaultRegion(config.GetPhoneNumberDefaultRegion())
	if err != nil {
		return errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	config.PhoneNumberDefaultRegion = region
	return nil
}
