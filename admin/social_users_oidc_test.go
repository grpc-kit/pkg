package admin

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-kit/pkg/auth"
)

func TestVerifyOIDCIDToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                                provider.URL,
				"authorization_endpoint":                provider.URL + "/authorize",
				"token_endpoint":                        provider.URL + "/token",
				"jwks_uri":                              provider.URL + "/keys",
				"response_types_supported":              []string{"code"},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"keys": []map[string]string{{
					"kty": "RSA",
					"use": "sig",
					"alg": "RS256",
					"kid": "test-key",
					"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	s := &socialUsers{oauthCfg: &oauthConfigData{Issuer: provider.URL, ClientID: "client-1"}}
	claims := &auth.IDTokenClaims{CommonClaims: auth.CommonClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    provider.URL,
			Subject:   "provider-user-1",
			Audience:  jwt.ClaimStrings{"client-1"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		PreferredUsername: "alice",
		Email:             "alice@example.com",
		EmailVerified:     true,
	}}
	claims.PhoneNumber = "+8613900001234"
	claims.PhoneNumberVerified = true
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key"
	rawIDToken, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	got, err := s.verifyOIDCIDToken(t.Context(), rawIDToken)
	if err != nil {
		t.Fatalf("verifyOIDCIDToken: %v", err)
	}
	if got.Subject != claims.Subject || got.Email != claims.Email || got.PhoneNumber != claims.PhoneNumber || !got.PhoneNumberVerified {
		t.Fatalf("verified claims mismatch: %#v", got)
	}

	t.Run("wrong audience", func(t *testing.T) {
		wrongAudience := *claims
		wrongAudience.Audience = jwt.ClaimStrings{"another-client"}
		wrongToken := jwt.NewWithClaims(jwt.SigningMethodRS256, &wrongAudience)
		wrongToken.Header["kid"] = "test-key"
		raw, signErr := wrongToken.SignedString(privateKey)
		if signErr != nil {
			t.Fatalf("SignedString: %v", signErr)
		}
		if _, verifyErr := s.verifyOIDCIDToken(t.Context(), raw); verifyErr == nil {
			t.Fatal("expected wrong audience to be rejected")
		}
	})

	t.Run("wrong signature", func(t *testing.T) {
		otherKey, keyErr := rsa.GenerateKey(rand.Reader, 2048)
		if keyErr != nil {
			t.Fatalf("GenerateKey: %v", keyErr)
		}
		wrongToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		wrongToken.Header["kid"] = "test-key"
		raw, signErr := wrongToken.SignedString(otherKey)
		if signErr != nil {
			t.Fatalf("SignedString: %v", signErr)
		}
		if _, verifyErr := s.verifyOIDCIDToken(t.Context(), raw); verifyErr == nil {
			t.Fatal("expected wrong signature to be rejected")
		}
	})
}

func TestExternalUserClaimsFromIDToken(t *testing.T) {
	claims := &auth.IDTokenClaims{CommonClaims: auth.CommonClaims{
		RegisteredClaims:  jwt.RegisteredClaims{Subject: "provider-subject"},
		PreferredUsername: "preferred-user",
		Email:             "user@example.com",
		EmailVerified:     true,
	}}
	claims.PhoneNumber = "+8613900001234"
	claims.PhoneNumberVerified = true
	profile := externalUserClaimsFromIDToken(claims)
	if profile.ProviderSubject != "provider-subject" || profile.Username != "preferred-user" || profile.PhoneNumber != claims.PhoneNumber || !profile.PhoneNumberVerified {
		t.Fatalf("profile mapping mismatch: %#v", profile)
	}
}

func TestGetMapBoolRequiresExplicitBoolean(t *testing.T) {
	if !getMapBool(map[string]interface{}{"email_verified": true}, "email_verified") {
		t.Fatal("explicit true was not recognized")
	}
	for _, value := range []interface{}{false, "true", 1, nil} {
		if getMapBool(map[string]interface{}{"email_verified": value}, "email_verified") {
			t.Fatalf("untrusted value was accepted: %#v", value)
		}
	}
}
