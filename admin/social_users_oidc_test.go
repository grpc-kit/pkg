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

	t.Run("上游联邦扩展不影响普通登录", func(t *testing.T) {
		payload, err := json.Marshal(claims)
		if err != nil {
			t.Fatal(err)
		}
		var upstream jwt.MapClaims
		if err := json.Unmarshal(payload, &upstream); err != nil {
			t.Fatal(err)
		}
		upstream["federated_claims"] = map[string]string{
			"connector_id": "upstream-ldap", "user_id": "another-id", "username": "another-name", "tenant_id": "org-a",
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, upstream)
		token.Header["kid"] = "test-key"
		raw, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		verified, err := s.verifyOIDCIDToken(t.Context(), raw)
		if err != nil {
			t.Fatalf("上游字符串扩展导致普通 OIDC 登录失败：%v", err)
		}
		profile := externalUserClaimsFromIDToken(verified)
		if profile.ProviderSubject != claims.Subject || profile.Username != claims.PreferredUsername {
			t.Fatal("上游嵌套联邦资料替换了本次认证的主体或用户名")
		}
	})

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
	if profile.ProviderSubject != "provider-subject" || profile.Username != "preferred-user" || profile.UsernameIsFallback || profile.RawUsername != "preferred-user" || profile.PhoneNumber != claims.PhoneNumber || !profile.PhoneNumberVerified {
		t.Fatalf("profile mapping mismatch: %#v", profile)
	}
	profile = externalUserClaimsFromIDToken(&auth.IDTokenClaims{CommonClaims: auth.CommonClaims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "provider-subject"},
	}})
	if !profile.UsernameIsFallback || profile.ProviderSubject != "provider-subject" {
		t.Fatalf("subject promoted to username: %#v", profile)
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

func TestOAuthUserinfoSubject(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
	}{
		{"integer", `{"id":42}`, "42"},
		{"zero", `{"id":0}`, "0"},
		{"upper-bound", `{"id":9007199254740991}`, "9007199254740991"},
		{"lower-bound", `{"id":-9007199254740991}`, "-9007199254740991"},
		{"large-string", `{"id":"9007199254740993"}`, "9007199254740993"},
		{"opaque-string", `{"id":"00042.part"}`, "00042.part"},
		{"missing-field-fallback", `{"sub":"original-subject"}`, "original-subject"},
		{"above-limit", `{"id":9007199254740992}`, ""},
		{"below-limit", `{"id":-9007199254740992}`, ""},
		{"integer-overflow", `{"id":9223372036854775808}`, ""},
		{"fraction", `{"id":42.9}`, ""},
		{"fraction-that-rounds-to-integer", `{"id":42.0000000000000001}`, ""},
		{"exponent", `{"id":4.2e1}`, ""},
		{"boolean", `{"id":true}`, ""},
		{"object", `{"id":{"value":42}}`, ""},
		{"array", `{"id":[42]}`, ""},
		{"whitespace-string", `{"id":" 42 ","sub":"fallback"}`, ""},
		{"empty-string-no-fallback", `{"id":"","sub":"fallback"}`, ""},
		{"null-no-fallback", `{"id":null,"sub":"fallback"}`, ""},
		{"missing-subject", `{}`, ""},
		{"null-document", `null`, ""},
		{"trailing-value", `{"id":42} {"id":43}`, ""},
		{"trailing-garbage", `{"id":42}garbage`, ""},
		{"trailing-whitespace", "{\"id\":42}\n\t", "42"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			userinfo, err := decodeOAuthUserinfo([]byte(tc.body))
			var got string
			if err == nil {
				got, err = oauthUserinfoSubject(userinfo, "id")
			}
			if tc.want == "" {
				if err == nil || got != "" {
					t.Fatal("invalid userinfo produced a subject")
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("subject=%q err=%v, want %q", got, err, tc.want)
			}
		})
	}
	// The subject parser must never trust an already lossy numeric map value.
	if _, err := oauthUserinfoSubject(map[string]any{"id": float64(42)}, "id"); err == nil {
		t.Fatal("pre-decoded float64 accepted as an external subject")
	}
	profile, err := decodeOAuthUserinfo([]byte(`{"id":42,"display":42.9,"name":" Alice "}`))
	if err != nil || getMapString(profile, "display") != "42" || getMapString(profile, "name") != "Alice" {
		t.Fatal("subject decoding changed legacy profile formatting")
	}
}
