package admin

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

const (
	defaultLDAPUserIDAttribute = "uid"
	legacyLDAPUserIDAttribute  = "dn"
	maxLDAPProviderUserIDRunes = 255
)

var ldapAttributeDescriptionPattern = regexp.MustCompile(
	`^(?:[A-Za-z][A-Za-z0-9-]*|[0-9]+(?:\.[0-9]+)+)(?:;[A-Za-z0-9-]+)*$`,
)

// normalizeLDAPUserIDAttributeName validates an LDAP AttributeDescription.
// LDAP descriptors and numeric OIDs are both accepted. Known attributes use
// stable display casing so JSON and audit comparisons remain deterministic.
func normalizeLDAPUserIDAttributeName(raw string) (string, error) {
	attribute := strings.TrimSpace(raw)
	if attribute == "" {
		return "", fmt.Errorf("ldap user_id_attribute must not be empty")
	}

	switch {
	case strings.EqualFold(attribute, legacyLDAPUserIDAttribute):
		return legacyLDAPUserIDAttribute, nil
	case strings.EqualFold(attribute, "uid"):
		return "uid", nil
	case strings.EqualFold(attribute, "uidNumber"):
		return "uidNumber", nil
	case strings.EqualFold(attribute, "entryUUID"):
		return "entryUUID", nil
	case strings.EqualFold(attribute, "objectGUID"):
		return "objectGUID", nil
	}

	if !ldapAttributeDescriptionPattern.MatchString(attribute) {
		return "", fmt.Errorf("ldap user_id_attribute is not a valid LDAP attribute description")
	}
	return attribute, nil
}

func effectiveLDAPUserIDAttribute(config *ldapConfigData) string {
	if config == nil || config.UserIDAttribute == nil {
		return legacyLDAPUserIDAttribute
	}
	return strings.TrimSpace(*config.UserIDAttribute)
}

func normalizeLDAPProviderUserID(attribute, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("ldap user_id_attribute %s is empty", attribute)
	}

	var normalized string
	switch {
	case strings.EqualFold(attribute, "uidNumber"):
		number, err := strconv.ParseUint(trimmed, 10, 64)
		if err != nil {
			return "", fmt.Errorf("ldap user_id_attribute uidNumber is invalid: %w", err)
		}
		normalized = strconv.FormatUint(number, 10)
	case strings.EqualFold(attribute, "entryUUID"):
		parsed, err := uuid.Parse(trimmed)
		if err != nil {
			return "", fmt.Errorf("ldap user_id_attribute entryUUID is invalid: %w", err)
		}
		normalized = parsed.String()
	default:
		normalized = trimmed
	}

	if err := validateLDAPProviderUserID(normalized); err != nil {
		return "", err
	}
	return normalized, nil
}

func normalizeADObjectGUID(raw []byte) (string, error) {
	if len(raw) != 16 {
		return "", fmt.Errorf("ldap user_id_attribute objectGUID must contain exactly 16 bytes")
	}

	// Active Directory encodes the first three GUID fields in little-endian
	// byte order and the remaining eight bytes in network order.
	canonical := uuid.UUID{
		raw[3], raw[2], raw[1], raw[0],
		raw[5], raw[4],
		raw[7], raw[6],
		raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
	}.String()
	return canonical, nil
}

func resolveLDAPProviderUserID(entry *ldap.Entry, configuredAttribute string) (string, error) {
	if entry == nil {
		return "", fmt.Errorf("ldap user entry is nil")
	}

	attribute, err := normalizeLDAPUserIDAttributeName(configuredAttribute)
	if err != nil {
		return "", err
	}
	if attribute == legacyLDAPUserIDAttribute {
		return normalizeLDAPProviderUserID(attribute, entry.DN)
	}

	if attribute == "objectGUID" {
		values := entry.GetEqualFoldRawAttributeValues(attribute)
		if len(values) == 0 {
			return "", fmt.Errorf("ldap user_id_attribute objectGUID is missing")
		}
		if len(values) != 1 {
			return "", fmt.Errorf("ldap user_id_attribute objectGUID must be single-valued")
		}
		value, err := normalizeADObjectGUID(values[0])
		if err != nil {
			return "", err
		}
		if err := validateLDAPProviderUserID(value); err != nil {
			return "", err
		}
		return value, nil
	}

	values := entry.GetEqualFoldAttributeValues(attribute)
	if len(values) == 0 {
		return "", fmt.Errorf("ldap user_id_attribute %s is missing", attribute)
	}
	if len(values) != 1 {
		return "", fmt.Errorf("ldap user_id_attribute %s must be single-valued", attribute)
	}
	return normalizeLDAPProviderUserID(attribute, values[0])
}

func validateLDAPProviderUserID(value string) error {
	if value == "" {
		return fmt.Errorf("ldap provider_user_id must not be empty")
	}
	if utf8.RuneCountInString(value) > maxLDAPProviderUserIDRunes {
		return fmt.Errorf("ldap provider_user_id exceeds %d characters", maxLDAPProviderUserIDRunes)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("ldap provider_user_id contains control characters")
		}
	}
	return nil
}
