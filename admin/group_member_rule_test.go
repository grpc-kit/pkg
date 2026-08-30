package admin

import (
	"strings"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
)

func TestParseAndValidateUserFilterCanonicalizes(t *testing.T) {
	rule, err := parseAndValidateUserFilter(" Status=active  and TYPE != employee AND email_verified=TRUE ")
	if err != nil {
		t.Fatalf("parse rule: %v", err)
	}
	want := "status = ACTIVE AND type != EMPLOYEE AND email_verified = true"
	if rule.canonical != want {
		t.Fatalf("canonical = %q, want %q", rule.canonical, want)
	}
	user := &lion.Users{
		UserStatus:    int(adminv1.User_ACTIVE),
		UserType:      int(adminv1.User_ADMIN),
		EmailVerified: true,
	}
	if !rule.matches(user) {
		t.Fatal("expected rule to match user")
	}
}

func TestParseAndValidateUserFilterRejectsUnsupportedSyntax(t *testing.T) {
	tests := []string{
		"",
		"timezone = Asia/Shanghai",
		"locale = en-US",
		"gender = PRIVATE",
		"status >= ACTIVE",
		"status = ACTIVE OR type = ADMIN",
		"status = ACTIVE AND",
		"status = 2",
		"email_verified = 'true'",
		"status = TYPE_UNSPECIFIED",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			if _, err := parseAndValidateUserFilter(input); err == nil {
				t.Fatalf("expected %q to be rejected", input)
			}
		})
	}
}

func TestParseAndValidateUserFilterLimits(t *testing.T) {
	conditions := make([]string, maxUserFilterConditions+1)
	for i := range conditions {
		conditions[i] = "status = ACTIVE"
	}
	if _, err := parseAndValidateUserFilter(strings.Join(conditions, " AND ")); err == nil {
		t.Fatal("expected condition limit error")
	}
	if _, err := parseAndValidateUserFilter(strings.Repeat("x", maxUserFilterBytes+1)); err == nil {
		t.Fatal("expected byte limit error")
	}
}

func TestDecodeStoredUserFilterRejectsUnknownFields(t *testing.T) {
	if _, err := decodeStoredUserFilter([]byte(`{"user_filter":"status = ACTIVE","unknown":true}`)); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestParseAndValidateUserFilterErrorsOmitRawValue(t *testing.T) {
	// §4.1.4：错误信息只含 condition 序号、字段和错误类别，不得回显原始值。
	tests := []string{
		"status = 2",
		"type = SECRET",
		"email_verified = MAYBE",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			_, err := parseAndValidateUserFilter(input)
			if err == nil {
				t.Fatalf("expected %q to be rejected", input)
			}
			rawValue := input[strings.LastIndex(input, " ")+1:]
			if strings.Contains(err.Error(), rawValue) {
				t.Fatalf("error %q leaks raw value %q", err, rawValue)
			}
		})
	}
}
