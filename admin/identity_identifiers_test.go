package admin

import (
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"google.golang.org/protobuf/proto"
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

func TestNormalizeExternalPhoneNumber(t *testing.T) {
	fromE164, err := normalizeExternalPhoneNumber("+86 139 0000 1234", "")
	if err != nil {
		t.Fatalf("normalizeExternalPhoneNumber(E.164): %v", err)
	}
	fromNational, err := normalizeExternalPhoneNumber("13900001234", " cn ")
	if err != nil {
		t.Fatalf("normalizeExternalPhoneNumber(national): %v", err)
	}
	if fromE164.Identifier != fromNational.Identifier {
		t.Fatalf("normalized identifiers differ: E.164=%+v national=%+v", fromE164.Identifier, fromNational.Identifier)
	}
	if got := fromE164.Proto.GetCountryCode(); got != "86" {
		t.Fatalf("country code = %q, want 86", got)
	}
	if got := fromE164.Proto.GetNationalNumber(); got != "13900001234" {
		t.Fatalf("national number = %q, want 13900001234", got)
	}
	if fromE164.Identifier.CanonicalValue != "+8613900001234" {
		t.Fatalf("canonical value = %q, want +8613900001234", fromE164.Identifier.CanonicalValue)
	}

	withTrunkPrefix, err := normalizeExternalPhoneNumber("07912 345 678", "GB")
	if err != nil {
		t.Fatalf("normalizeExternalPhoneNumber(trunk prefix): %v", err)
	}
	if withTrunkPrefix.Identifier.CanonicalValue != "+447912345678" {
		t.Fatalf("trunk-prefix canonical value = %q, want +447912345678", withTrunkPrefix.Identifier.CanonicalValue)
	}
}

func TestNormalizeExternalPhoneNumberRejectsUnsupportedValues(t *testing.T) {
	for _, tt := range []struct {
		name          string
		value         string
		defaultRegion string
	}{
		{name: "empty", value: "", defaultRegion: "CN"},
		{name: "national without region", value: "13900001234"},
		{name: "invalid region", value: "13900001234", defaultRegion: "XX"},
		{name: "invalid number", value: "+86123"},
		{name: "fixed line", value: "+442083661177"},
		{name: "extension", value: "+8613900001234 ext. 12"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := normalizeExternalPhoneNumber(tt.value, tt.defaultRegion); err == nil {
				t.Fatalf("normalizeExternalPhoneNumber(%q, %q) error = nil", tt.value, tt.defaultRegion)
			}
		})
	}
}

func TestNormalizePhoneNumberDefaultRegion(t *testing.T) {
	for _, tt := range []struct {
		input   string
		want    string
		wantErr bool
	}{
		{input: " cn ", want: "CN"},
		{input: "", want: ""},
		{input: "XX", wantErr: true},
	} {
		got, err := normalizePhoneNumberDefaultRegion(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("normalizePhoneNumberDefaultRegion(%q) error = nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Fatalf("normalizePhoneNumberDefaultRegion(%q): %v", tt.input, err)
		}
		if got != tt.want {
			t.Fatalf("normalizePhoneNumberDefaultRegion(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestEncryptPhoneNumberUsesUserProtoFormat(t *testing.T) {
	phone := &adminv1.PhoneNumber{CountryCode: "86", NationalNumber: "13900001234"}
	s := &socialUsers{aesKey: []byte("0123456789abcdef0123456789abcdef")}

	encrypted, err := s.encryptPhoneNumber(phone)
	if err != nil {
		t.Fatalf("encryptPhoneNumber: %v", err)
	}
	raw, err := crypto.DecryptAES(s.aesKey, encrypted)
	if err != nil {
		t.Fatalf("DecryptAES: %v", err)
	}
	decoded := &adminv1.PhoneNumber{}
	if err := proto.Unmarshal(raw, decoded); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	if !proto.Equal(decoded, phone) {
		t.Fatalf("decoded phone = %+v, want %+v", decoded, phone)
	}
}
