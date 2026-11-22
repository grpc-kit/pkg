package cfg

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/viper"
)

func TestOIDCDiscoveryConfigAndSnapshot(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(`
security:
  enable: true
  authentication:
    oidc_provider:
      issuer: https://issuer.example.test
      config:
        discovery_url: https://discovery.example.test/metadata?tenant=example
        client_id: client-1
        client_secret: test-secret
        redirect_uri: https://app.example.test/auth/callback
        scopes:
          - openid
          - profile
          - custom:read
`)); err != nil {
		t.Fatal(err)
	}
	c, err := New(v)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://discovery.example.test/metadata?tenant=example"
	if c.Security.Authentication.OIDCProvider.Config.DiscoveryURL != want {
		t.Fatal("discovery_url was not loaded from YAML")
	}
	config := c.Security.Authentication.OIDCProvider.Config
	wantScopes := []string{"openid", "profile", "custom:read"}
	if config.ClientSecret != "test-secret" || config.RedirectURI != "https://app.example.test/auth/callback" || !slices.Equal(config.Scopes, wantScopes) {
		t.Fatal("OIDC client configuration was not loaded from YAML")
	}
	provider := c.toAdminSecurityConfig().GetAuthentication().GetOidcProvider()
	if provider.GetIssuer() != "https://issuer.example.test" || provider.GetConfig().GetDiscoveryUrl() != want {
		t.Fatalf("OIDC snapshot mismatch: %v", provider)
	}
	if provider.GetConfig().GetClientSecret() != maskedValue {
		t.Fatal("OIDC client secret was not masked")
	}
	if provider.GetConfig().GetRedirectUri() != config.RedirectURI || !slices.Equal(provider.GetConfig().GetScopes(), wantScopes) {
		t.Fatal("OIDC client configuration was not included in the snapshot")
	}
}

func TestOIDCClientConfigRemainsOptional(t *testing.T) {
	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(strings.NewReader(`
security:
  authentication:
    oidc_provider:
      issuer: https://issuer.example.test
      config:
        client_id: client-1
`)); err != nil {
		t.Fatal(err)
	}
	c, err := New(v)
	if err != nil {
		t.Fatal(err)
	}
	config := c.Security.Authentication.OIDCProvider.Config
	if config.ClientSecret != "" || config.RedirectURI != "" || len(config.Scopes) != 0 {
		t.Fatal("optional OIDC client configuration acquired defaults")
	}
	snapshot := c.toAdminSecurityConfig().GetAuthentication().GetOidcProvider().GetConfig()
	if snapshot.GetClientSecret() != "" || snapshot.GetRedirectUri() != "" || len(snapshot.GetScopes()) != 0 {
		t.Fatal("optional OIDC client configuration acquired snapshot defaults")
	}
}

func TestInitSecurityOIDCDiscoveryVerification(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path, issuerPath string
		custom, tls, retry     bool
		advertised, explicit   []string
		method                 jwt.SigningMethod
	}{
		{name: "standard", path: "/tenant/.well-known/openid-configuration", issuerPath: "/tenant"},
		{name: "standard trailing slash", path: "/tenant/.well-known/openid-configuration", issuerPath: "/tenant/"},
		{name: "custom query", custom: true, path: "/metadata/custom?tenant=example&version=2", issuerPath: "/tenant"},
		{name: "custom TLS", custom: true, tls: true, path: "/metadata", issuerPath: "/tenant"},
		{name: "custom retry", custom: true, retry: true, path: "/metadata", issuerPath: "/tenant"},
		{name: "filtered algorithms default to RS256", custom: true, path: "/metadata", issuerPath: "/tenant", advertised: []string{"HS256", "none", "unknown"}},
		{name: "advertised PS256", custom: true, path: "/metadata", issuerPath: "/tenant", advertised: []string{"PS256"}, method: jwt.SigningMethodPS256},
		{name: "explicit algorithm overrides metadata", custom: true, path: "/metadata", issuerPath: "/tenant", advertised: []string{"RS256"}, explicit: []string{"PS256"}, method: jwt.SigningMethodPS256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var discoveries atomic.Int32
			var keyRequests atomic.Int32
			var server *httptest.Server
			server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.RequestURI() {
				case tc.path:
					if discoveries.Add(1) == 1 && tc.retry {
						http.Error(w, "test-sensitive-response", http.StatusServiceUnavailable)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"issuer": server.URL + tc.issuerPath, "jwks_uri": server.URL + "/keys",
						"id_token_signing_alg_values_supported": tc.advertised,
					})
				case "/keys":
					keyRequests.Add(1)
					_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
						"kty": "RSA", "use": "sig", "kid": "test-key",
						"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
						"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
					}}})
				default:
					t.Errorf("unexpected OIDC request: %s", r.URL.RequestURI())
					http.NotFound(w, r)
				}
			}))
			if tc.tls {
				server.StartTLS()
			} else {
				server.Start()
			}
			t.Cleanup(server.Close)
			config := &OIDCConfig{ClientID: "client-1", InsecureSkipVerify: tc.tls, SupportedSigningAlgs: tc.explicit}
			if tc.custom {
				config.DiscoveryURL = server.URL + tc.path
			}
			records := make(chan capturedSecurityLog, 8)
			c := &LocalConfig{
				logger: slog.New(&securityChannelHandler{records: records}),
				Security: &SecurityConfig{Enable: true, Authentication: &Authentication{
					OIDCProvider: &OIDCProvider{Issuer: server.URL + tc.issuerPath, Config: config},
				}},
			}
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			if err := c.initSecurity(ctx); err != nil {
				t.Fatal(err)
			}
			timeout := time.NewTimer(5 * time.Second)
			defer timeout.Stop()
		ready:
			for {
				select {
				case record := <-records:
					if strings.Contains(record.message, "test-sensitive-response") || len(record.attrs) != 0 {
						t.Fatal("discovery details leaked into logs")
					}
					if record.message == "OIDC verifier is ready" {
						break ready
					}
				case <-timeout.C:
					t.Fatal("OIDC verifier was not initialized")
				}
			}
			wantDiscoveries := int32(1)
			if tc.retry {
				wantDiscoveries = 2
			}
			if discoveries.Load() != wantDiscoveries {
				t.Fatalf("discovery requests = %d, want %d", discoveries.Load(), wantDiscoveries)
			}
			method := tc.method
			if method == nil {
				method = jwt.SigningMethodRS256
			}
			for _, failure := range []string{"", "issuer", "audience", "expired", "signature", "algorithm"} {
				t.Run("token "+failure, func(t *testing.T) {
					claims := jwt.RegisteredClaims{
						Issuer: server.URL + tc.issuerPath, Subject: "42", Audience: jwt.ClaimStrings{"client-1"},
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
					}
					signingKey := any(key)
					signingMethod := method
					switch failure {
					case "issuer":
						claims.Issuer = server.URL + "/another-issuer"
					case "audience":
						claims.Audience = jwt.ClaimStrings{"another-client"}
					case "expired":
						claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
					case "signature":
						signingKey = otherKey
					case "algorithm":
						signingMethod, signingKey = jwt.SigningMethodHS256, []byte("test-hmac-secret")
					}
					token := jwt.NewWithClaims(signingMethod, claims)
					token.Header["kid"] = "test-key"
					raw, err := token.SignedString(signingKey)
					if err != nil {
						t.Fatal(err)
					}
					verified, err := c.Security.verifyBearerToken(t.Context(), raw)
					if failure == "" {
						if err != nil || verified.Subject != "42" {
							t.Fatalf("verify valid token: subject=%q, error=%v", verified.Subject, err)
						}
					} else if err == nil {
						t.Fatalf("accepted token with wrong %s", failure)
					}
				})
			}
			if keyRequests.Load() == 0 {
				t.Fatal("verifier did not fetch JWKS")
			}
		})
	}
}

func TestOIDCDiscoveryRejectsInvalidMetadata(t *testing.T) {
	for _, tc := range []struct {
		name, body, want string
		status           int
	}{
		{name: "HTTP error", status: http.StatusNotFound, body: "test-sensitive-response", want: "HTTP 404"},
		{name: "invalid JSON", body: `{"issuer":`, want: "decode"},
		{name: "trailing JSON", body: `{} {}`, want: "decode"},
		{name: "null metadata", body: `null`, want: "issuer"},
		{name: "missing issuer", body: `{"jwks_uri":"https://issuer.example.test/keys"}`, want: "issuer"},
		{name: "wrong issuer", body: `{"issuer":"https://another.example.test","jwks_uri":"https://issuer.example.test/keys"}`, want: "issuer"},
		{name: "missing keys", body: `{"issuer":"https://issuer.example.test"}`, want: "jwks_uri"},
		{name: "relative keys", body: `{"issuer":"https://issuer.example.test","jwks_uri":"/keys"}`, want: "jwks_uri"},
		{name: "oversized document", body: strings.Repeat(" ", oidcDiscoveryMaxSize+1), want: "size limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/custom" {
					t.Errorf("unexpected discovery fallback: %s", r.URL.Path)
				}
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				_, _ = io.WriteString(w, tc.body)
			}))
			t.Cleanup(server.Close)
			provider, err := discoverOIDCProvider(t.Context(), "https://issuer.example.test", server.URL+"/custom")
			if provider != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("provider=%v, error=%v, want %q", provider, err, tc.want)
			}
			if strings.Contains(err.Error(), "test-sensitive-response") {
				t.Fatal("discovery response body leaked into error")
			}
		})
	}
}

func TestInitSecurityRejectsInvalidDiscoveryConfig(t *testing.T) {
	for _, value := range []string{"/metadata", "metadata", "ftp://example.test/metadata", "https:///metadata", "https://example.test:bad/metadata", "https://user:secret@example.test/metadata", "https://example.test/metadata#fragment", " https://example.test/metadata"} {
		t.Run(value, func(t *testing.T) {
			c := &LocalConfig{Security: &SecurityConfig{Enable: true, Authentication: &Authentication{
				OIDCProvider: &OIDCProvider{Issuer: "https://issuer.example.test", Config: &OIDCConfig{DiscoveryURL: value}},
			}}}
			if err := c.initSecurity(t.Context()); err == nil || !strings.Contains(err.Error(), "discovery_url") || strings.Contains(err.Error(), "secret") {
				t.Fatalf("invalid discovery_url error = %v", err)
			}
		})
	}
	for _, config := range []*OIDCConfig{nil, {DiscoveryURL: "https://example.test/metadata"}} {
		c := &LocalConfig{Security: &SecurityConfig{Enable: true, Authentication: &Authentication{
			OIDCProvider: &OIDCProvider{Config: config},
		}}}
		if err := c.initSecurity(t.Context()); err == nil || !strings.Contains(err.Error(), "issuer") {
			t.Fatalf("missing issuer error = %v", err)
		}
	}
}

func TestInitSecurityDiscoveryIssuerCheckCannotBeSkipped(t *testing.T) {
	for _, custom := range []bool{false, true} {
		name := "standard"
		if custom {
			name = "custom"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"issuer": "https://another.example.test", "jwks_uri": "https://another.example.test/keys",
				})
			}))
			t.Cleanup(server.Close)
			config := &OIDCConfig{SkipIssuerCheck: true, SkipClientIDCheck: true}
			if custom {
				config.DiscoveryURL = server.URL + "/custom"
			}
			records := make(chan capturedSecurityLog, 4)
			c := &LocalConfig{
				logger: slog.New(&securityChannelHandler{records: records}),
				Security: &SecurityConfig{Enable: true, Authentication: &Authentication{
					OIDCProvider: &OIDCProvider{Issuer: server.URL, Config: config},
				}},
			}
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			if err := c.initSecurity(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case record := <-records:
				if record.message != "OIDC provider discovery failed; retrying" {
					t.Fatalf("unexpected discovery log: %s", record.message)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("discovery did not reject the mismatched issuer")
			}
			if _, ok := c.Security.idTokenVerifier(); ok {
				t.Fatal("verifier accepted discovery issuer mismatch despite SkipIssuerCheck")
			}
			cancel()
			select {
			case record := <-records:
				if record.message != "OIDC verifier initialization stopped" {
					t.Fatalf("unexpected cancellation log: %s", record.message)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("discovery retry did not stop after cancellation")
			}
		})
	}
}

func TestOIDCDiscoveryCancellationAndTLS(t *testing.T) {
	t.Run("cancellation", func(t *testing.T) {
		started := make(chan struct{})
		stopped := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			close(started)
			<-r.Context().Done()
			close(stopped)
		}))
		t.Cleanup(server.Close)
		ctx, cancel := context.WithCancel(t.Context())
		t.Cleanup(cancel)
		result := make(chan error, 1)
		go func() {
			_, err := discoverOIDCProvider(ctx, server.URL, server.URL+"/custom")
			result <- err
		}()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("discovery request did not start")
		}
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation error = %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("discovery did not return after cancellation")
		}
		select {
		case <-stopped:
		case <-time.After(5 * time.Second):
			t.Fatal("HTTP request did not observe cancellation")
		}
	})
	t.Run("untrusted TLS", func(t *testing.T) {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Error("untrusted TLS request reached handler")
		}))
		server.Config.ErrorLog = log.New(io.Discard, "", 0)
		server.StartTLS()
		t.Cleanup(server.Close)
		if _, err := discoverOIDCProvider(t.Context(), server.URL, server.URL+"/custom"); err == nil {
			t.Fatal("untrusted TLS certificate was accepted")
		}
	})
}

type discoveryRoundTripper func(*http.Request) (*http.Response, error)

func (f discoveryRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOIDCDiscoveryRequestTimeout(t *testing.T) {
	client := &http.Client{Transport: discoveryRoundTripper(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if remaining := time.Until(deadline); !ok || remaining <= 0 || remaining > oidcDiscoveryTimeout {
			t.Errorf("unexpected discovery deadline: %v, present=%v", deadline, ok)
		}
		return nil, context.DeadlineExceeded
	})}
	ctx := oidc.ClientContext(t.Context(), client)
	_, err := discoverOIDCProvider(ctx, "https://issuer.example.test", "https://discovery.example.test/custom")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v", err)
	}
}
