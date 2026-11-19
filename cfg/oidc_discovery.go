package cfg

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	oidcDiscoveryTimeout = 10 * time.Second
	oidcDiscoveryMaxSize = 1 << 20
)

func validateOIDCDiscoveryURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("must be an absolute HTTP(S) URL without user credentials or fragment")
	}
	return nil
}

// discoverOIDCProvider loads metadata for the local token verifier. The custom
// path uses ProviderConfig, whose Provider does not retain raw discovery claims.
func discoverOIDCProvider(ctx context.Context, issuer, discoveryURL string) (*oidc.Provider, error) {
	if discoveryURL == "" {
		return oidc.NewProvider(ctx, issuer)
	}
	if err := validateOIDCDiscoveryURL(discoveryURL); err != nil {
		return nil, err
	}

	requestCtx, cancel := context.WithTimeout(ctx, oidcDiscoveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create OIDC discovery request: %w", err)
	}
	client := http.DefaultClient
	if configured, ok := ctx.Value(oauth2.HTTPClient).(*http.Client); ok && configured != nil {
		client = configured
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request OIDC discovery document: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, oidcDiscoveryMaxSize+1))
	if err != nil {
		return nil, fmt.Errorf("read OIDC discovery document: %w", err)
	}
	if len(body) > oidcDiscoveryMaxSize {
		return nil, fmt.Errorf("OIDC discovery document exceeds size limit")
	}
	var metadata oidc.ProviderConfig
	if err := json.Unmarshal(body, &metadata); err != nil {
		return nil, fmt.Errorf("decode OIDC discovery document: %w", err)
	}
	// ProviderConfig.NewProvider skips discovery validation. Keep issuer equality
	// independent of SkipIssuerCheck, which only applies to token verification.
	if metadata.IssuerURL != issuer {
		return nil, fmt.Errorf("OIDC discovery issuer does not match configured issuer")
	}
	if err := validateOIDCDiscoveryURL(metadata.JWKSURL); err != nil {
		return nil, fmt.Errorf("OIDC discovery jwks_uri: %w", err)
	}
	// Match go-oidc v3.15.0 NewProvider's algorithm filtering. Explicit verifier
	// algorithms still take precedence; an empty list retains its RS256 default.
	algorithms := make([]string, 0, len(metadata.Algorithms))
	for _, algorithm := range metadata.Algorithms {
		switch algorithm {
		case oidc.RS256, oidc.RS384, oidc.RS512,
			oidc.ES256, oidc.ES384, oidc.ES512,
			oidc.PS256, oidc.PS384, oidc.PS512, oidc.EdDSA:
			algorithms = append(algorithms, algorithm)
		}
	}
	metadata.Algorithms = algorithms
	// Pass the original context to retain the HTTP client for JWKS requests;
	// the discovery-only timeout must not become the verifier's lifetime.
	return metadata.NewProvider(ctx), nil
}
