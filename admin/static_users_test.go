package admin

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/crypto"
)

func TestStaticUsersValid(t *testing.T) {
	plain := "mysecret"
	clientPayload := crypto.SHA256([]byte(plain))
	users := StaticUsers{
		&StaticUser{Username: "u1", PasswordHash: clientPayload},
	}

	u, ok := users.Valid("u1", clientPayload)
	if !ok || u == nil || u.Username != "u1" {
		t.Fatalf("sha256 hex user: ok=%v u=%v", ok, u)
	}

	_, ok = users.Valid("u1", "wrong")
	if ok {
		t.Fatal("expected mismatch")
	}

	bcryptStored := crypto.BcryptHashMust(clientPayload)
	users2 := StaticUsers{
		&StaticUser{Username: "u2", PasswordHash: bcryptStored},
	}
	u2, ok2 := users2.Valid("u2", clientPayload)
	if !ok2 || u2 == nil {
		t.Fatalf("bcrypt user: ok=%v u=%v", ok2, u2)
	}
}

func TestStaticUserAccessTokenUsesConfiguredPasswordHashAsHMACKey(t *testing.T) {
	const passwordHash = "already-derived-password-hash"
	user := StaticUser{
		UserID:       42,
		Username:     "static-user",
		PasswordHash: passwordHash,
		Groups:       []string{"admin"},
	}

	tokenString, err := user.GetAccessToken(3600, "legacy-app")
	if err != nil {
		t.Fatalf("GetAccessToken: %v", err)
	}

	var claims auth.AccessTokenClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(passwordHash), nil
	})
	if err != nil {
		t.Fatalf("ParseWithClaims: %v", err)
	}
	if !token.Valid {
		t.Fatal("token is not valid")
	}
	if claims.Subject != "42" || claims.Appid != "legacy-app" {
		t.Fatalf("claims mismatch: sub=%q appid=%q", claims.Subject, claims.Appid)
	}
}
