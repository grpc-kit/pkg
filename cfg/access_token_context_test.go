package cfg

import (
	"context"
	"testing"

	"github.com/grpc-kit/pkg/auth"
)

func TestAccessTokenFromKeepsLegacyIDTokenProjection(t *testing.T) {
	c := &LocalConfig{}
	want := auth.AccessTokenClaims{
		CommonClaims: auth.CommonClaims{
			Username: "context-user",
			Email:    "context-user@example.com",
		},
		ClientID: "client-1",
		Scope:    "openid",
	}
	want.SetSubject("123")

	ctx := context.Background()
	ctx = (&SecurityConfig{}).withIDToken(ctx, want)

	got, ok := c.AccessTokenFrom(ctx)
	if !ok || got.ClientID != want.ClientID || got.Scope != want.Scope {
		t.Fatalf("AccessTokenFrom() = %#v, %v", got, ok)
	}
	legacy, ok := c.IDTokenFrom(ctx)
	if !ok || legacy.Subject != want.Subject || legacy.Username != want.Username {
		t.Fatalf("IDTokenFrom() compatibility projection = %#v, %v", legacy, ok)
	}
}
