package admin

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/crypto"
)

func testStaticIssuance(clientID string) AccessTokenIssuanceContext {
	return AccessTokenIssuanceContext{
		ClientID: clientID,
		Tenant:   "default",
		TTL:      time.Hour,
	}
}

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
	if claims.Subject != "42" || claims.ClientID != "legacy-app" || claims.Appid != "" {
		t.Fatalf("claims mismatch: sub=%q client_id=%q appid=%q", claims.Subject, claims.ClientID, claims.Appid)
	}
	if claims.Issuer != "" || len(claims.Audience) != 0 {
		t.Fatalf("issuer/audience must be omitted: iss=%q aud=%v", claims.Issuer, claims.Audience)
	}
	if claims.PreferredUsername != "static-user" || claims.Username != "" {
		t.Fatalf("username claims mismatch: preferred=%q username=%q", claims.PreferredUsername, claims.Username)
	}
	if typ := token.Header["typ"]; typ != "at+jwt" {
		t.Fatalf("static access token typ = %v, want at+jwt", typ)
	}
}

func TestStaticUserAccessTokenSeparatesRolesAndGroups(t *testing.T) {
	const passwordHash = "password-hash"
	newUser := StaticUser{UserID: 1, Username: "new", PasswordHash: passwordHash, Roles: []string{"admin"}, Groups: []string{"engineering"}}
	groupsOnlyUser := StaticUser{UserID: 2, Username: "groups-only", PasswordHash: passwordHash, Groups: []string{"engineering"}}
	for _, tc := range []struct {
		name                  string
		user                  StaticUser
		wantRoles, wantGroups []string
	}{
		{"new", newUser, []string{"admin"}, []string{"engineering"}},
		{"groups-only", groupsOnlyUser, nil, []string{"engineering"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenString, err := tc.user.issueAccessToken(testStaticIssuance("app"))
			if err != nil {
				t.Fatal(err)
			}
			var claims auth.AccessTokenClaims
			if _, err := jwt.ParseWithClaims(tokenString, &claims, func(*jwt.Token) (interface{}, error) { return []byte(passwordHash), nil }); err != nil {
				t.Fatal(err)
			}
			if len(claims.Roles) != len(tc.wantRoles) || (len(tc.wantRoles) > 0 && claims.Roles[0] != tc.wantRoles[0]) {
				t.Fatalf("roles=%v", claims.Roles)
			}
			if len(claims.Groups) != len(tc.wantGroups) || (len(tc.wantGroups) > 0 && claims.Groups[0] != tc.wantGroups[0]) {
				t.Fatalf("groups=%v", claims.Groups)
			}
			if len(auth.EffectiveRoles(claims)) != len(tc.wantRoles) {
				t.Fatalf("effective roles=%v", auth.EffectiveRoles(claims))
			}
		})
	}
}
