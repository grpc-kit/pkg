package admin

import (
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
)

func TestCanonicalizeEmailIdentifier(t *testing.T) {
	got, err := canonicalizeEmailIdentifier("  Alice.Example+ops@Example.COM  ")
	if err != nil {
		t.Fatalf("canonicalizeEmailIdentifier: %v", err)
	}
	if got.StoredValue != "Alice.Example+ops@Example.COM" || got.CanonicalValue != "alice.example+ops@example.com" {
		t.Fatalf("unexpected email canonicalization: %+v", got)
	}
	if got.Hash != crypto.SHA256([]byte(got.CanonicalValue)) {
		t.Fatalf("email hash = %q, want hash of canonical value", got.Hash)
	}
}

func TestCanonicalizeEmailIdentifierRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"", "alice", "Alice <alice@example.com>", "alice @example.com", "a@@example.com"} {
		if _, err := canonicalizeEmailIdentifier(value); err == nil {
			t.Fatalf("canonicalizeEmailIdentifier(%q) error = nil", value)
		}
	}
}

func TestCanonicalizePhoneIdentifiers(t *testing.T) {
	fromParts, err := canonicalizePhoneNumberIdentifier(&adminv1.PhoneNumber{CountryCode: "+86", NationalNumber: "13900001234"})
	if err != nil {
		t.Fatalf("canonicalizePhoneNumberIdentifier: %v", err)
	}
	fromString, err := canonicalizeE164PhoneIdentifier(" +8613900001234 ")
	if err != nil {
		t.Fatalf("canonicalizeE164PhoneIdentifier: %v", err)
	}
	if fromParts.CanonicalValue != "+8613900001234" || fromParts != fromString {
		t.Fatalf("phone canonicalization mismatch: parts=%+v string=%+v", fromParts, fromString)
	}
	if fromParts.Hash != crypto.SHA256([]byte(fromParts.CanonicalValue)) {
		t.Fatalf("phone hash = %q, want hash of canonical value", fromParts.Hash)
	}
}

func TestCanonicalizePhoneIdentifiersRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"", "8613900001234", "+08613900001234", "+86 13900001234", "+1234567890123456"} {
		if _, err := canonicalizeE164PhoneIdentifier(value); err == nil {
			t.Fatalf("canonicalizeE164PhoneIdentifier(%q) error = nil", value)
		}
	}
	for _, value := range []*adminv1.PhoneNumber{
		nil,
		{},
		{CountryCode: "0", NationalNumber: "123"},
		{CountryCode: "86", NationalNumber: "139-0000-1234"},
	} {
		if _, err := canonicalizePhoneNumberIdentifier(value); err == nil {
			t.Fatalf("canonicalizePhoneNumberIdentifier(%v) error = nil", value)
		}
	}
}
