package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	pkgerrs "github.com/grpc-kit/pkg/errs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCanonicalVerifiedIdentifierHashes(t *testing.T) {
	s := &socialUsers{}
	tests := []struct {
		name      string
		claims    verifiedIdentityClaims
		wantEmail bool
		wantPhone bool
	}{
		{name: "both verified", claims: verifiedIdentityClaims{Email: "Alice@Example.com", EmailVerified: true, PhoneNumber: "+8613900001234", PhoneNumberVerified: true}, wantEmail: true, wantPhone: true},
		{name: "unverified ignored", claims: verifiedIdentityClaims{Email: "alice@example.com", PhoneNumber: "+8613900001234"}},
		{name: "invalid verified ignored", claims: verifiedIdentityClaims{Email: "invalid", EmailVerified: true, PhoneNumber: "13900001234", PhoneNumberVerified: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.canonicalVerifiedIdentifierHashes(tt.claims)
			if (got.email != "") != tt.wantEmail || (got.phone != "") != tt.wantPhone {
				t.Fatalf("hashes = %+v, want email=%v phone=%v", got, tt.wantEmail, tt.wantPhone)
			}
		})
	}
}

func TestConvergeVerifiedIdentifierOwners(t *testing.T) {
	tests := []struct {
		name                    string
		emailID, phoneID        int
		emailFound, phoneFound  bool
		wantID                  int
		wantFound, wantConflict bool
	}{
		{name: "none", emailID: 0, phoneID: 0},
		{name: "email", emailID: 10, emailFound: true, wantID: 10, wantFound: true},
		{name: "phone", phoneID: 20, phoneFound: true, wantID: 20, wantFound: true},
		{name: "same user", emailID: 30, phoneID: 30, emailFound: true, phoneFound: true, wantID: 30, wantFound: true},
		{name: "different users", emailID: 30, phoneID: 31, emailFound: true, phoneFound: true, wantConflict: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userID, found, err := convergeVerifiedIdentifierOwners(tt.emailID, tt.emailFound, tt.phoneID, tt.phoneFound)
			if userID != tt.wantID || found != tt.wantFound || errors.Is(err, errExternalVerifiedIdentifiersConflict) != tt.wantConflict {
				t.Fatalf("result = (%d, %v, %v), want (%d, %v, conflict=%v)", userID, found, err, tt.wantID, tt.wantFound, tt.wantConflict)
			}
		})
	}
}

func TestExternalEmailAlreadyExistsPublicError(t *testing.T) {
	err := externalEmailAlreadyExistsPublicError(context.Background())
	st := status.Convert(err)
	if st.Code() != codes.AlreadyExists {
		t.Fatalf("status code = %v, want %v", st.Code(), codes.AlreadyExists)
	}
	if httpCode := pkgerrs.FromError(err).HTTPStatusCode(); httpCode != http.StatusConflict {
		t.Fatalf("HTTP status = %d, want %d", httpCode, http.StatusConflict)
	}
	if !strings.Contains(st.Message(), "email") || !strings.Contains(st.Message(), "bind this provider") {
		t.Fatalf("status message is not actionable: %q", st.Message())
	}
}

func TestExternalIdentityAlreadyBoundPublicError(t *testing.T) {
	err := externalIdentityAlreadyBoundPublicError(context.Background())
	st := status.Convert(err)
	if st.Code() != codes.AlreadyExists {
		t.Fatalf("status code = %v, want %v", st.Code(), codes.AlreadyExists)
	}
	if !strings.Contains(st.Message(), "already bound") {
		t.Fatalf("status message is not actionable: %q", st.Message())
	}
}

func TestExternalPhoneAlreadyExistsPublicError(t *testing.T) {
	err := externalPhoneAlreadyExistsPublicError(context.Background())
	st := status.Convert(err)
	if st.Code() != codes.AlreadyExists || !strings.Contains(st.Message(), "phone number") {
		t.Fatalf("status = (%v, %q), want AlreadyExists phone message", st.Code(), st.Message())
	}
}

func TestExternalVerifiedIdentifiersConflictPublicError(t *testing.T) {
	err := externalVerifiedIdentifiersConflictPublicError(context.Background())
	st := status.Convert(err)
	if st.Code() != codes.AlreadyExists || !strings.Contains(st.Message(), "different users") {
		t.Fatalf("status = (%v, %q), want AlreadyExists conflict message", st.Code(), st.Message())
	}
}
