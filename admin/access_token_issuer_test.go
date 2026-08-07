package admin

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-kit/pkg/auth"
)

func TestBuildAccessTokenClaims(t *testing.T) {
	issuedAt := time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)
	claims, err := BuildAccessTokenClaims(AccessTokenInput{
		Subject:           " 42 ",
		PreferredUsername: " alice ",
		Email:             " alice@example.com ",
		EmailVerified:     true,
		Roles:             []string{"viewer", " admin ", "admin", ""},
		Groups:            []string{"engineering", "engineering"},
		ClientID:          " admin-web ",
		Scope:             "profile openid profile",
		TTL:               time.Hour,
		IssuedAt:          issuedAt,
		JWTID:             "jti-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "42" || claims.ClientID != "admin-web" {
		t.Fatalf("standard claims mismatch: %+v", claims)
	}
	if claims.Issuer != "" || len(claims.Audience) != 0 {
		t.Fatalf("issuer/audience must be omitted: iss=%q aud=%v", claims.Issuer, claims.Audience)
	}
	if claims.ExpiresAt == nil || !claims.ExpiresAt.Time.Equal(issuedAt.Add(time.Hour)) {
		t.Fatalf("expires_at = %v", claims.ExpiresAt)
	}
	if claims.IssuedAt == nil || !claims.IssuedAt.Time.Equal(issuedAt) || claims.ID != "jti-1" {
		t.Fatalf("issued_at/jti mismatch: iat=%v jti=%q", claims.IssuedAt, claims.ID)
	}
	if claims.NotBefore != nil {
		t.Fatalf("nbf should be omitted: %v", claims.NotBefore)
	}
	if want := []string{"admin", "viewer"}; !reflect.DeepEqual(claims.Roles, want) {
		t.Fatalf("roles = %v, want %v", claims.Roles, want)
	}
	if want := []string{"engineering"}; !reflect.DeepEqual(claims.Groups, want) {
		t.Fatalf("groups = %v, want %v", claims.Groups, want)
	}
	if claims.Scope != "openid profile" || claims.Tenant != "" {
		t.Fatalf("scope/tenant mismatch: scope=%q tenant=%q", claims.Scope, claims.Tenant)
	}
	if claims.Email != "alice@example.com" || !claims.EmailVerified || claims.Appid != "" {
		t.Fatalf("email/appid mismatch: email=%q verified=%t appid=%q", claims.Email, claims.EmailVerified, claims.Appid)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatal(err)
	}
	for _, omitted := range []string{"iss", "aud", "appid", "nbf", "tenant"} {
		if _, ok := fields[omitted]; ok {
			t.Fatalf("claim %q must be omitted from payload: %s", omitted, payload)
		}
	}
}

func TestBuildAccessTokenClaimsOmitsMissingEmail(t *testing.T) {
	claims, err := BuildAccessTokenClaims(AccessTokenInput{
		Subject:       "42",
		EmailVerified: true,
		ClientID:      "admin-web",
		TTL:           time.Hour,
		IssuedAt:      time.Now(),
		JWTID:         "jti-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if claims.Email != "" || claims.EmailVerified {
		t.Fatalf("missing email must not be synthesized or verified: %+v", claims.CommonClaims)
	}
}

func TestBuildAccessTokenClaimsRejectsIncompleteContext(t *testing.T) {
	valid := AccessTokenInput{
		Subject:  "42",
		ClientID: "admin-web",
		TTL:      time.Hour,
		IssuedAt: time.Now(),
		JWTID:    "jti-valid",
	}
	tests := map[string]func(*AccessTokenInput){
		"subject":   func(input *AccessTokenInput) { input.Subject = "" },
		"client_id": func(input *AccessTokenInput) { input.ClientID = "" },
		"ttl":       func(input *AccessTokenInput) { input.TTL = 0 },
		"issued_at": func(input *AccessTokenInput) { input.IssuedAt = time.Time{} },
		"jti":       func(input *AccessTokenInput) { input.JWTID = "" },
	}
	for name, invalidate := range tests {
		t.Run(name, func(t *testing.T) {
			input := valid
			invalidate(&input)
			if _, err := BuildAccessTokenClaims(input); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestStaticIssuerUsesRawHMACKey(t *testing.T) {
	now := time.Now().UTC()
	issuer := &accessTokenIssuer{
		now:      func() time.Time { return now },
		newJWTID: func() string { return "fixed-jti" },
	}
	input := AccessTokenInput{
		Subject:  "42",
		ClientID: "admin-web",
		TTL:      time.Hour,
	}
	key := []byte("already-derived-password-hash")
	tokenString, err := issuer.issueStaticHS256(input, key)
	if err != nil {
		t.Fatal(err)
	}
	var claims auth.AccessTokenClaims
	token, err := jwt.ParseWithClaims(tokenString, &claims, func(*jwt.Token) (interface{}, error) {
		return key, nil
	})
	if err != nil || !token.Valid {
		t.Fatalf("token verification failed: %v", err)
	}
	if token.Header["typ"] != "at+jwt" || claims.ID != "fixed-jti" {
		t.Fatalf("header/claims mismatch: header=%v jti=%q", token.Header, claims.ID)
	}
}
