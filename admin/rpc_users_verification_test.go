package admin

import (
	"strings"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
)

func TestValidateCreateUserVerificationState(t *testing.T) {
	tests := []struct {
		name    string
		user    *adminv1.User
		wantErr string
	}{
		{
			name: "verified email with value",
			user: &adminv1.User{Email: "alice@example.com", EmailVerified: true},
		},
		{
			name:    "verified email without value",
			user:    &adminv1.User{EmailVerified: true},
			wantErr: "email_verified requires email",
		},
		{
			name: "verified complete phone number",
			user: &adminv1.User{
				PhoneNumber:         &adminv1.PhoneNumber{CountryCode: "86", NationalNumber: "13800138000"},
				PhoneNumberVerified: true,
			},
		},
		{
			name: "verified incomplete phone number",
			user: &adminv1.User{
				PhoneNumber:         &adminv1.PhoneNumber{CountryCode: "86"},
				PhoneNumberVerified: true,
			},
			wantErr: "phone_number_verified requires a complete phone_number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCreateUserVerificationState(tt.user)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateCreateUserVerificationState() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateCreateUserVerificationState() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
