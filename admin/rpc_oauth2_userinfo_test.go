package admin

import (
	"context"
	"testing"

	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestGetOAuth2UserinfoSupportsBasicAuth(t *testing.T) {
	api := New()
	ctx := rpc.ContextWithAuthenticationType(context.Background(), "basic")
	ctx = rpc.ContextWithUserID(ctx, 3)
	ctx = rpc.ContextWithUsername(ctx, "user1")

	got, err := api.GetOAuth2Userinfo(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Sub != "3" || got.UserId != 3 || got.PreferredUsername != "user1" {
		t.Fatalf("userinfo mismatch: %+v", got)
	}
}

func TestGetOAuth2UserinfoPrefersVerifiedTokenClaims(t *testing.T) {
	api := New()
	claims := auth.AccessTokenClaims{CommonClaims: auth.CommonClaims{
		PreferredUsername: "token-user",
		Email:             "token@example.com",
		EmailVerified:     true,
	}}
	claims.SetSubject("9")

	ctx := rpc.ContextWithAuthenticationType(context.Background(), "basic")
	ctx = rpc.ContextWithUserID(ctx, 3)
	ctx = rpc.ContextWithUsername(ctx, "basic-user")
	ctx = rpc.ContextWithTokenClaims(ctx, claims)

	got, err := api.GetOAuth2Userinfo(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Sub != "9" || got.UserId != 9 || got.PreferredUsername != "token-user" || got.Email != "token@example.com" {
		t.Fatalf("userinfo did not prefer token claims: %+v", got)
	}
}

func TestGetOAuth2UserinfoRejectsMissingAuthentication(t *testing.T) {
	api := New()
	if _, err := api.GetOAuth2Userinfo(context.Background(), &emptypb.Empty{}); err == nil {
		t.Fatal("expected unauthenticated context to be rejected")
	}
}
