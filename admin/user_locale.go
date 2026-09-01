package admin

import (
	"fmt"
	"strings"
	"time"
	_ "time/tzdata"

	"golang.org/x/text/language"
)

func normalizeUserTimezone(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	// Bare abbreviations (for example CST/EST) are ambiguous even when a host
	// zoneinfo installation happens to provide a file with that name. Bare
	// names that are explicitly present in the pinned IANA Link table remain
	// valid aliases and are canonicalized below.
	if _, knownAlias := ianaTimezoneAliases[value]; value != "UTC" && !strings.Contains(value, "/") && !knownAlias {
		return "", fmt.Errorf("timezone must be an IANA area/location name")
	}
	seen := make(map[string]struct{})
	for {
		target, ok := ianaTimezoneAliases[value]
		if !ok {
			break
		}
		if _, duplicate := seen[value]; duplicate {
			return "", fmt.Errorf("timezone alias cycle")
		}
		seen[value] = struct{}{}
		value = target
	}
	if value != "UTC" && !strings.Contains(value, "/") {
		return "", fmt.Errorf("timezone must be an IANA zone name")
	}
	if strings.HasPrefix(value, "+") || strings.HasPrefix(value, "-") || strings.Contains(value, "GMT+") || strings.Contains(value, "GMT-") {
		return "", fmt.Errorf("fixed-offset timezone is not allowed")
	}
	if _, err := time.LoadLocation(value); err != nil {
		return "", fmt.Errorf("invalid IANA timezone: %w", err)
	}
	return value, nil
}

func normalizeUserLocale(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if strings.Contains(value, "_") || strings.ContainsAny(value, " \t\r\n") {
		return "", fmt.Errorf("locale must use BCP 47 hyphen separators")
	}
	tag, err := language.Parse(value)
	if err != nil {
		return "", fmt.Errorf("invalid BCP 47 locale: %w", err)
	}
	canonical := tag.String()
	if tag == language.Und || canonical == "und" || strings.HasPrefix(canonical, "und-") {
		return "", fmt.Errorf("locale must identify a language")
	}
	return canonical, nil
}

func normalizeUserLocaleFields(timezone, locale string) (string, string, error) {
	timezone, err := normalizeUserTimezone(timezone)
	if err != nil {
		return "", "", err
	}
	locale, err = normalizeUserLocale(locale)
	if err != nil {
		return "", "", err
	}
	return timezone, locale, nil
}
