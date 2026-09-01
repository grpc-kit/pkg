package admin

import (
	"fmt"
	"net/mail"
	"strings"
	"unicode"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
)

const maxE164Digits = 15

// canonicalIdentifier is the single representation used for identifier
// lookup and persistence. Raw user/provider input must not be hashed directly.
type canonicalIdentifier struct {
	StoredValue    string
	CanonicalValue string
	Hash           string
}

func canonicalizeEmailIdentifier(raw string) (canonicalIdentifier, error) {
	stored := strings.TrimSpace(raw)
	if stored == "" {
		return canonicalIdentifier{}, fmt.Errorf("email is empty")
	}
	if len(stored) > 254 || strings.IndexFunc(stored, unicode.IsSpace) >= 0 || strings.IndexFunc(stored, unicode.IsControl) >= 0 {
		return canonicalIdentifier{}, fmt.Errorf("email format is invalid")
	}
	parsed, err := mail.ParseAddress(stored)
	if err != nil || parsed.Name != "" || parsed.Address != stored {
		return canonicalIdentifier{}, fmt.Errorf("email format is invalid")
	}
	parts := strings.Split(stored, "@")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return canonicalIdentifier{}, fmt.Errorf("email format is invalid")
	}

	canonical := strings.ToLower(stored)
	return canonicalIdentifier{
		StoredValue:    stored,
		CanonicalValue: canonical,
		Hash:           crypto.SHA256([]byte(canonical)),
	}, nil
}

func canonicalizePhoneNumberIdentifier(value *adminv1.PhoneNumber) (canonicalIdentifier, error) {
	if value == nil {
		return canonicalIdentifier{}, fmt.Errorf("phone number is empty")
	}
	countryCode := strings.TrimSpace(value.GetCountryCode())
	countryCode = strings.TrimPrefix(countryCode, "+")
	nationalNumber := strings.TrimSpace(value.GetNationalNumber())
	return canonicalizePhoneParts(countryCode, nationalNumber)
}

func canonicalizeE164PhoneIdentifier(raw string) (canonicalIdentifier, error) {
	canonical := strings.TrimSpace(raw)
	if len(canonical) < 3 || canonical[0] != '+' {
		return canonicalIdentifier{}, fmt.Errorf("phone number must use E.164 format")
	}
	digits := canonical[1:]
	if !isDecimalDigits(digits) || digits[0] == '0' || len(digits) > maxE164Digits {
		return canonicalIdentifier{}, fmt.Errorf("phone number must use E.164 format")
	}
	return canonicalIdentifier{
		StoredValue:    canonical,
		CanonicalValue: canonical,
		Hash:           crypto.SHA256([]byte(canonical)),
	}, nil
}

func canonicalizePhoneParts(countryCode, nationalNumber string) (canonicalIdentifier, error) {
	if !isDecimalDigits(countryCode) || !isDecimalDigits(nationalNumber) || countryCode[0] == '0' {
		return canonicalIdentifier{}, fmt.Errorf("phone number must contain a valid country code and national number")
	}
	if len(countryCode)+len(nationalNumber) > maxE164Digits {
		return canonicalIdentifier{}, fmt.Errorf("phone number exceeds E.164 length")
	}
	return canonicalizeE164PhoneIdentifier("+" + countryCode + nationalNumber)
}

func isDecimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
