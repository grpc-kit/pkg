package admin

import (
	"fmt"
	"net/mail"
	"strconv"
	"strings"
	"unicode"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/nyaruka/phonenumbers/v2"
)

const maxE164Digits = 15

// canonicalIdentifier is the single representation used for identifier
// lookup and persistence. Raw user/provider input must not be hashed directly.
type canonicalIdentifier struct {
	StoredValue    string
	CanonicalValue string
	Hash           string
}

type normalizedPhoneNumber struct {
	Proto      *adminv1.PhoneNumber
	Identifier canonicalIdentifier
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

func normalizeExternalPhoneNumber(raw, defaultRegion string) (normalizedPhoneNumber, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return normalizedPhoneNumber{}, fmt.Errorf("phone number is empty")
	}

	region := strings.ToUpper(strings.TrimSpace(defaultRegion))
	if !strings.HasPrefix(value, "+") && region == "" {
		return normalizedPhoneNumber{}, fmt.Errorf("phone number must use E.164 format when default region is empty")
	}
	if region != "" && !phonenumbers.GetSupportedRegions()[region] {
		return normalizedPhoneNumber{}, fmt.Errorf("phone number default region is invalid")
	}

	parsed, err := phonenumbers.Parse(value, region)
	if err != nil {
		return normalizedPhoneNumber{}, fmt.Errorf("parse phone number: %w", err)
	}
	if parsed.GetExtension() != "" {
		return normalizedPhoneNumber{}, fmt.Errorf("phone number extensions are not supported")
	}
	if !phonenumbers.IsValidNumber(parsed) {
		return normalizedPhoneNumber{}, fmt.Errorf("phone number is invalid")
	}
	numberType := phonenumbers.GetNumberType(parsed)
	if numberType != phonenumbers.MOBILE && numberType != phonenumbers.FIXED_LINE_OR_MOBILE {
		return normalizedPhoneNumber{}, fmt.Errorf("phone number is not a mobile number")
	}

	e164 := phonenumbers.Format(parsed, phonenumbers.E164)
	countryCode := strconv.FormatInt(int64(parsed.GetCountryCode()), 10)
	nationalNumber, ok := strings.CutPrefix(e164, "+"+countryCode)
	if !ok || nationalNumber == "" {
		return normalizedPhoneNumber{}, fmt.Errorf("phone number cannot be represented in E.164 format")
	}

	phoneNumber := &adminv1.PhoneNumber{
		CountryCode:    countryCode,
		NationalNumber: nationalNumber,
	}
	identifier, err := canonicalizePhoneNumberIdentifier(phoneNumber)
	if err != nil {
		return normalizedPhoneNumber{}, err
	}
	if identifier.CanonicalValue != e164 {
		return normalizedPhoneNumber{}, fmt.Errorf("phone number canonicalization mismatch")
	}
	return normalizedPhoneNumber{
		Proto:      phoneNumber,
		Identifier: identifier,
	}, nil
}

func normalizePhoneNumberDefaultRegion(raw string) (string, error) {
	region := strings.ToUpper(strings.TrimSpace(raw))
	if region == "" {
		return "", nil
	}
	if !phonenumbers.GetSupportedRegions()[region] {
		return "", fmt.Errorf("phone_number_default_region must be a supported ISO 3166-1 alpha-2 region")
	}
	return region, nil
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
