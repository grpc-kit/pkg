package admin

import (
	"strings"
	"testing"
)

func TestNormalizeUserTimezone(t *testing.T) {
	tests := map[string]string{
		"":              "",
		" UTC ":         "UTC",
		"Etc/UTC":       "UTC",
		"GMT":           "UTC",
		"US/Eastern":    "America/New_York",
		"Asia/Calcutta": "Asia/Kolkata",
		"Asia/Shanghai": "Asia/Shanghai",
	}
	for input, want := range tests {
		got, err := normalizeUserTimezone(input)
		if err != nil {
			t.Fatalf("normalize %q: %v", input, err)
		}
		if got != want {
			t.Fatalf("normalize %q = %q, want %q", input, got, want)
		}
	}
	for _, input := range []string{"CST", "+08:00", "GMT+8", "Not/AZone"} {
		if _, err := normalizeUserTimezone(input); err == nil {
			t.Fatalf("expected %q to be rejected", input)
		}
	}
	for alias := range ianaTimezoneAliases {
		got, err := normalizeUserTimezone(alias)
		if err != nil {
			t.Fatalf("normalize pinned IANA alias %q: %v", alias, err)
		}
		if got != "UTC" && !strings.Contains(got, "/") {
			t.Fatalf("alias %q normalized to non-canonical zone %q", alias, got)
		}
	}
}

func TestNormalizeUserLocale(t *testing.T) {
	for input, want := range map[string]string{
		"":      "",
		"zh-cn": "zh-CN",
		"EN-us": "en-US",
	} {
		got, err := normalizeUserLocale(input)
		if err != nil {
			t.Fatalf("normalize %q: %v", input, err)
		}
		if got != want {
			t.Fatalf("normalize %q = %q, want %q", input, got, want)
		}
	}
	for _, input := range []string{"und", "not_a_locale"} {
		if _, err := normalizeUserLocale(input); err == nil {
			t.Fatalf("expected %q to be rejected", input)
		}
	}
}
