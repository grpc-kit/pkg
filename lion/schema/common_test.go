package schema

import "testing"

func TestValidateCode_AllowsDotSeparatedNames(t *testing.T) {
	validCodes := []string{
		"order.read",
		"order-read",
		"order.read-v2",
		"a1",
	}

	for _, code := range validCodes {
		if err := ValidateCode(code); err != nil {
			t.Fatalf("ValidateCode(%q) returned unexpected error: %v", code, err)
		}
	}
}

func TestValidateCode_RejectsInvalidSeparators(t *testing.T) {
	invalidCodes := []string{
		"order..read",
		"order--read",
		"order-.read",
		"order.-read",
		"order.",
		".order",
	}

	for _, code := range invalidCodes {
		if err := ValidateCode(code); err == nil {
			t.Fatalf("ValidateCode(%q) expected error, got nil", code)
		}
	}
}
