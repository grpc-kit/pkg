package admin

import (
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestStaticUsersRejectAmbiguousIdentities(t *testing.T) {
	const first, second = "review-service-155", "review-service-380"
	id := crypto.Username2UserID(first)
	if id != crypto.Username2UserID(second) {
		t.Fatal("collision fixture changed")
	}
	for name, users := range map[string]StaticUsers{
		"derived collision":  {{Username: first}, {Username: second}},
		"mixed collision":    {{Username: first, UserID: id}, {Username: second}},
		"explicit collision": {{Username: first, UserID: id}, {Username: second, UserID: id}},
		"duplicate username": {{Username: first}, {Username: first}},
		"database ID":        {{Username: first, UserID: 123456}},
		"empty name":         {{Username: " "}},
		"nil entry":          {nil},
	} {
		t.Run(name, func(t *testing.T) {
			if err := users.Validate(); err == nil {
				t.Fatal("accepted invalid static identities")
			}
			if _, ok := users.FindByUserID(id); ok {
				t.Fatal("resolved an ambiguous or invalid identity")
			}
			if _, ok := users.Valid(first, ""); ok {
				t.Fatal("authenticated an invalid user list")
			}
		})
	}
}

func TestStaticUserRejectsInvalidIDAtIssuance(t *testing.T) {
	user := StaticUser{Username: "oneops", UserID: 123456, PasswordHash: "test-only-key"}
	if token, err := user.GetAccessToken(3600, "test-client"); err == nil || token != "" {
		t.Fatal("issued a token with a database ID for a static identity")
	}
}

func TestAuthRejectsInvalidStaticConfiguration(t *testing.T) {
	for name, users := range map[string]StaticUsers{
		"database ID": {{Username: "oneops", UserID: 123456, PasswordHash: "test-only-key"}},
		"collision":   {{Username: "review-service-155"}, {Username: "review-service-380"}},
	} {
		t.Run(name, func(t *testing.T) {
			api := New(WithStaticUsers(&users))
			ctx := callerTokenContext("oneops", crypto.Username2UserID("oneops"), []string{"superadmin"}, nil, "")
			_, err := api.CreateAuthToken(ctx, &adminv1.CreateAuthTokenRequest{ClientId: "test-client"})
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("token issuance error = %v, want FailedPrecondition", err)
			}
			_, err = api.CreateAuthLogin(t.Context(), &adminv1.CreateAuthLoginRequest{Username: "oneops", PasswordHash: "test-only-key"})
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("login error = %v, want FailedPrecondition", err)
			}
		})
	}
}
