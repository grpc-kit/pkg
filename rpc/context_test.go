package rpc

import (
	"context"
	"testing"
)

type testTokenClaims struct {
	Subject string
}

func TestAccessTokenClaimsContext(t *testing.T) {
	want := testTokenClaims{Subject: "123"}

	ctx := ContextWithTokenClaims(context.Background(), want)
	got, ok := GetTokenClaimsFromContext(ctx).(testTokenClaims)
	if !ok {
		t.Fatal("GetTokenClaimsFromContext() did not find claims")
	}
	if got.Subject != want.Subject {
		t.Fatalf("claims = %#v, want %#v", got, want)
	}
}

func TestLegacyTokenContextRemainsReadable(t *testing.T) {
	want := testTokenClaims{Subject: "legacy-user"}
	ctx := ContextWithIDToken(context.Background(), want)

	got, ok := GetIDTokenFromContext(ctx).(testTokenClaims)
	if !ok || got.Subject != want.Subject {
		t.Fatalf("legacy claims = %#v, %v", got, ok)
	}
}
