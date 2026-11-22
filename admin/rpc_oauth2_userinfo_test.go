package admin

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/protobuf/encoding/protojson"
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

func TestGetOAuth2UserinfoOmitsFederatedClaims(t *testing.T) {
	api := New()
	t.Cleanup(func() { close(api.mfaChallenges.stopGC) })
	username := "Alice"
	common := auth.CommonClaims{
		PreferredUsername: "local-user",
		FederatedClaims:   &auth.FederatedClaims{ConnectorID: "ldap", Username: &username},
	}
	common.SetSubject("9")
	for _, token := range []any{
		auth.IDTokenClaims{CommonClaims: common},
		&auth.AccessTokenClaims{CommonClaims: common, ClientID: "test-client", Scope: "openid federated:username"},
	} {
		result, err := api.GetOAuth2Userinfo(rpc.ContextWithTokenClaims(t.Context(), token), &emptypb.Empty{})
		if err != nil {
			t.Fatalf("JWT 联邦资料不应改变普通 UserInfo 的读取条件：%v", err)
		}
		if result.Sub != "9" || result.PreferredUsername != "local-user" {
			t.Fatal("外部资料改写了 UserInfo 的本地身份")
		}
		data, err := (protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: true}).Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"federated_claims", "federatedClaims"} {
			if _, exists := fields[name]; exists {
				t.Fatalf("UserInfo 不应输出联邦资料：%s", data)
			}
		}
	}
}
