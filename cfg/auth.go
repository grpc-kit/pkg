package cfg

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt"
	"k8s.io/apimachinery/pkg/util/wait"
)

// IDTokenClaims 用于框架jwt的数据结构
type IDTokenClaims struct {
	jwt.StandardClaims
	Email           string            `json:"email"`
	EmailVerified   bool              `json:"email_verified"`
	Groups          []string          `json:"groups"`
	FederatedClaims map[string]string `json:"federated_claims"`
}

// InitAuthentication 初始化认证
func (c *LocalConfig) InitAuthentication() error {
	if !c.Security.Enable {
		return nil
	}

	if c.Security.Authentication == nil {
		return errors.New("security authentication enable but unset")
	}

	// 初始化jwt token认证
	if c.Security.Authentication.OIDCProvider != nil {
		if c.Security.Authentication.OIDCProvider.Issuer == "" {
			return errors.New("security authentication not found oidc issuer")
		}

		ctx := context.TODO()

		initVerifierFn := func() (done bool, err error) {
			oidcConfig := &oidc.Config{}
			if c.Security.Authentication.OIDCProvider.Config != nil {
				oidcConfig.ClientID = c.Security.Authentication.OIDCProvider.Config.ClientID
				oidcConfig.SupportedSigningAlgs = c.Security.Authentication.OIDCProvider.Config.SupportedSigningAlgs
				oidcConfig.SkipClientIDCheck = c.Security.Authentication.OIDCProvider.Config.SkipClientIDCheck
				oidcConfig.SkipExpiryCheck = c.Security.Authentication.OIDCProvider.Config.SkipExpiryCheck
				oidcConfig.SkipIssuerCheck = c.Security.Authentication.OIDCProvider.Config.SkipIssuerCheck

				if c.Security.Authentication.OIDCProvider.Config.InsecureSkipVerify {
					oidcClient := &http.Client{
						Transport: &http.Transport{
							TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
						},
					}
					ctx = oidc.ClientContext(ctx, oidcClient)
				}
			}

			provider, err := oidc.NewProvider(ctx, c.Security.Authentication.OIDCProvider.Issuer)
			if err != nil {
				c.logger.Errorf("oidc authenticator: initializing plugin: %v", err)
				return false, err
			}
			verifier := provider.Verifier(oidcConfig)
			c.Security.setVerifier(verifier)

			return true, nil
		}

		ok, err := initVerifierFn()
		if !ok || err != nil {
			go wait.PollUntil(time.Second*30, initVerifierFn, ctx.Done())
		}
	}

	return nil
}

// WithIDToken 用于设置当前会话的IDToken
func (c *LocalConfig) WithIDToken(parent context.Context, token IDTokenClaims) context.Context {
	return context.WithValue(parent, idTokenKey, token)
}

// WithUsername 用于设置当前会话的用户名
func (c *LocalConfig) WithUsername(parent context.Context, username string) context.Context {
	return context.WithValue(parent, usernameKey, username)
}

// WithAuthenticationType 用于设置当前会话的认证方式
func (c *LocalConfig) WithAuthenticationType(parent context.Context, authType string) context.Context {
	return context.WithValue(parent, authenticationTypeKey, authType)
}

// IDTokenFrom 用于获取当前会话的IDToken
func (c *LocalConfig) IDTokenFrom(ctx context.Context) (IDTokenClaims, bool) {
	idToken, ok := ctx.Value(idTokenKey).(IDTokenClaims)
	return idToken, ok
}

// UsernameFrom 用于获取当前会话的用户名
func (c *LocalConfig) UsernameFrom(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(usernameKey).(string)
	return username, ok
}

// AuthenticationTypeFrom 用于获取当前会话的认证方式
func (c *LocalConfig) AuthenticationTypeFrom(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(authenticationTypeKey).(string)
	return username, ok
}

// setVerifier 用于设置oidc verifier实例
func (s *SecurityConfig) setVerifier(v *oidc.IDTokenVerifier) {
	s.tokenVerifier.Store(v)
}

// idTokenVerifier 用于获取odic verifier实例
func (s *SecurityConfig) idTokenVerifier() (*oidc.IDTokenVerifier, bool) {
	if v := s.tokenVerifier.Load(); v != nil {
		return v.(*oidc.IDTokenVerifier), true
	}
	return nil, false
}
