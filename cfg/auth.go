package cfg

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jwt "github.com/golang-jwt/jwt/v4"
	"k8s.io/apimachinery/pkg/util/wait"
)

// IDTokenClaims 用于框架jwt的数据结构
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Email           string            `json:"email"`
	EmailVerified   bool              `json:"email_verified"`
	Groups          []string          `json:"groups"`
	FederatedClaims map[string]string `json:"federated_claims"`
}

// InitSecurity 初始化认证
func (c *LocalConfig) InitSecurity() error {
	if c.Security == nil {
		c.Security = &SecurityConfig{Enable: false}
	}

	if !c.Security.Enable {
		return nil
	}

	if c.Security.Authentication == nil {
		return fmt.Errorf("security authentication enable but unset")
	}

	// 初始化jwt token认证
	if c.Security.Authentication.OIDCProvider != nil {
		if c.Security.Authentication.OIDCProvider.Issuer == "" {
			return fmt.Errorf("security authentication not found oidc issuer")
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

// WithGroups 用于设置当前会话用户属于组
func (c *LocalConfig) WithGroups(parent context.Context, groups []string) context.Context {
	return context.WithValue(parent, groupsKey, groups)
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

// GroupsFrom 用于获取当前会话的用户组列表
func (c *LocalConfig) GroupsFrom(ctx context.Context) ([]string, bool) {
	groups, ok := ctx.Value(groupsKey).([]string)
	return groups, ok
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

// supportedHS256Alg 判断是否支持 hs256 签名算法
func (s *SecurityConfig) supportedHS256Alg() bool {
	if s == nil || s.Authentication == nil || s.Authentication.OIDCProvider == nil || s.Authentication.OIDCProvider.Config == nil {
		return false
	}
	for _, v := range s.Authentication.OIDCProvider.Config.SupportedSigningAlgs {
		if v == "HS256" {
			return true
		}
	}
	return false
}

// foundUserPassword 查找用户
func (s *SecurityConfig) foundUsername(user string) (bool, *BasicAuth) {
	if s.Authentication.HTTPUsers == nil {
		return false, nil
	}

	for _, v := range s.Authentication.HTTPUsers {
		if user == v.Username {
			return true, v
		}
	}

	return false, nil
}

// verifyBearerToken 用于验证 bearerToken
// 需判断服务端是否允许 HS256 的签名算法，如果有在判断 token 是否使用 HS256
func (s *SecurityConfig) verifyBearerToken(ctx context.Context, tokenString string) (IDTokenClaims, error) {
	var idToken IDTokenClaims

	// 用户提交的 token 是否为 HS256 签名
	hasHS256Alg := false

	// HS256 仅做该签名算法验证
	hs256Verify := func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() == "HS256" {
			hasHS256Alg = true

			claims, ok := token.Claims.(*IDTokenClaims)
			if ok {
				// 根据 sub 获取作为 username 获取对应的 password 作为 token 的签名验证
				f, b := s.foundUsername(claims.Subject)
				if f {
					return []byte(b.Password), nil
				}

				return nil, fmt.Errorf("not found key")
			}
		}

		return nil, nil
	}

	// 仅在服务端配置支持 HS256 算法时才执行
	if s.supportedHS256Alg() {
		token, err := jwt.ParseWithClaims(tokenString, &IDTokenClaims{}, hs256Verify)
		if hasHS256Alg && err != nil {
			if s.Authentication.OIDCProvider.Config == nil {
				return idToken, err
			}

			// 继续判断错误类型，忽略 token 过期等
			switch err {
			case jwt.ErrTokenExpired:
				if s.Authentication.OIDCProvider.Config.SkipExpiryCheck {
					return idToken, nil
				}
			default:
				return idToken, err
			}
		}

		if hasHS256Alg {
			if !token.Valid {
				return idToken, jwt.ErrInvalidKey
			}

			// 验证 issuer
			if !s.Authentication.OIDCProvider.Config.SkipIssuerCheck {
				if s.Authentication.OIDCProvider.Issuer != idToken.Issuer {
					return idToken, jwt.ErrTokenInvalidIssuer
				}
			}

			// 验证 client_id
			if !s.Authentication.OIDCProvider.Config.SkipClientIDCheck {
				if s.Authentication.OIDCProvider.Config == nil {
					return idToken, nil
				}
				clientID := s.Authentication.OIDCProvider.Config.ClientID
				if clientID != "" {
					if !idToken.VerifyAudience(clientID, true) {
						return idToken, jwt.ErrTokenInvalidAudience
					}
				}
			}

			return idToken, nil
		}
	}

	// TODO; 存在二次验证 token 考虑统一 oidc 类库
	// RS256 等其他签名算法验证
	tokenVerifier, ok := s.idTokenVerifier()
	if !ok {
		return idToken, jwt.ErrInvalidKey
	}
	token, err := tokenVerifier.Verify(ctx, tokenString)
	if err != nil {
		return idToken, err
	}
	if err := token.Claims(&idToken); err != nil {
		return idToken, err
	}

	return idToken, nil
}
