package cfg

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/rpc"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"
)

// IDTokenClaims 用于框架jwt的数据结构，使用 auth.IDTokenClaims 代替
/*
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Email           string            `json:"email"`
	EmailVerified   bool              `json:"email_verified"`
	Groups          []string          `json:"groups"`
	FederatedClaims map[string]string `json:"federated_claims"`
	Tenant          string            `json:"tenant"`
}
*/

// OPANative 内嵌的 opa 组件
type OPANative struct {
	Enabled *bool `mapstructure:"enabled"`
	Policy  struct {
		AuthFile string `mapstructure:"auth_file"`
		DataFile string `mapstructure:"data_file"`
	} `mapstructure:"policy"`
}

// OPAExternal 外部的 opa 服务
type OPAExternal struct {
	Enabled *bool  `mapstructure:"enabled"`
	Config  string `mapstructure:"config"`
}

// OPAEnvoyPlugin 使用 envoy 的 opa 插件服务
type OPAEnvoyPlugin struct {
	Enabled *bool `mapstructure:"enabled"`
	Service struct {
		GRPCAddress string `mapstructure:"grpc_address"`
	} `mapstructure:"service"`
}

// initSecurity 初始化认证
func (c *LocalConfig) initSecurity() error {
	if c.Security == nil {
		c.Security = &SecurityConfig{Enable: false}
	}

	// 初始化默认值
	falseVal := false
	// trueVal := true
	if c.Security.Authorization == nil {
		c.Security.Authorization = &Authorization{
			OPANative: OPANative{
				Enabled: &falseVal,
			},
			OPAExternal: OPAExternal{
				Enabled: &falseVal,
			},
		}
	}

	if c.Security.Authorization.OPANative.Enabled == nil {
		c.Security.Authorization.OPANative.Enabled = &falseVal
	}
	if c.Security.Authorization.OPAExternal.Enabled == nil {
		c.Security.Authorization.OPAExternal.Enabled = &falseVal
	}
	if c.Security.Authorization.OPAEnvoyPlugin.Enabled == nil {
		c.Security.Authorization.OPAEnvoyPlugin.Enabled = &falseVal
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
				c.logger.Debugf("oidc new provider failed will be retry: %v", err)
				// 这里返回错误后，就不会触发后续的重试
				return false, nil
			}
			verifier := provider.Verifier(oidcConfig)
			c.Security.setVerifier(verifier)

			return true, nil
		}

		// 初始化 oidc 认证器， 等待 verifier 初始化完成
		go func(initVerifierFn func() (done bool, err error)) {
			if err := wait.ExponentialBackoffWithContext(ctx, wait.Backoff{
				Duration: time.Second * 1, // 初始间隔
				Factor:   2,               // 每次翻倍
				Jitter:   0.0,             // 随机抖动，避免同时请求
				Steps:    300,             // 最大重试次数
				// Cap:      time.Second * 30, // 最大间隔
			}, func(ctx context.Context) (done bool, err error) {
				// 初始化 oidc 认证器， 等待 verifier 初始化完成
				// fmt.Println("start oidc authenticator: initializing plugin")

				return initVerifierFn()
			}); err != nil {
				c.logger.Errorf("oidc new provider verifier failed, initializing plugin exit err: %v", err)
			}

			c.logger.Infof("oid verifier is ready and polling for /.well-known/openid-configuration has been stopped")
		}(initVerifierFn)
	}

	return nil
}

// WithIDToken 用于设置当前会话的IDToken
func (c *SecurityConfig) withIDToken(parent context.Context, token auth.IDTokenClaims) context.Context {
	// return context.WithValue(parent, idTokenKey, token)
	return rpc.ContextWithIDToken(parent, token)
}

// WithUserID 用于设置当前会话的用户 ID
func (c *SecurityConfig) withUserID(parent context.Context, userID int64) context.Context {
	// return context.WithValue(parent, usernameKey, username)
	return rpc.ContextWithUserID(parent, userID)
}

// WithUsername 用于设置当前会话的用户名
func (c *SecurityConfig) withUsername(parent context.Context, username string) context.Context {
	// return context.WithValue(parent, usernameKey, username)
	return rpc.ContextWithUsername(parent, username)
}

// WithAuthenticationType 用于设置当前会话的认证方式
func (c *SecurityConfig) withAuthenticationType(parent context.Context, authType string) context.Context {
	// return context.WithValue(parent, authenticationTypeKey, authType)
	return rpc.ContextWithAuthenticationType(parent, authType)
}

// WithGroups 用于设置当前会话用户属于组
func (c *SecurityConfig) withGroups(parent context.Context, groups []string) context.Context {
	// return context.WithValue(parent, groupsKey, groups)
	return rpc.ContextWithGroups(parent, groups)
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
func (s *SecurityConfig) foundUserID(userID int64) (bool, *BasicAuth) {
	if s.Authentication.HTTPUsers == nil {
		return false, nil
	}

	for _, v := range s.Authentication.HTTPUsers {
		if userID == v.UserID {
			return true, v
		} else if v.UserID == 0 {
			// 兼容无 user_id 的用户
			if crypto.Username2UserID(v.Username) == userID {
				return true, v
			}
		}
	}

	return false, nil
}

// basicAuthEffectivePasswordHash 返回用于静态用户、JWT HS256 密钥及口令比较的“有效”材料：
// password_hash（trim 后非空）则原样返回；否则 password（trim 后非空）则返回其 SHA256 十六进制字符串。
func basicAuthEffectivePasswordHash(b *BasicAuth) string {
	if b == nil {
		return ""
	}
	ph := strings.TrimSpace(b.PasswordHash)
	if ph != "" {
		return ph
	}
	pw := strings.TrimSpace(b.Password)
	if pw != "" {
		return crypto.SHA256([]byte(pw))
	}
	return ""
}

// verifyBearerToken 用于验证 bearerToken
// 需判断服务端是否允许 HS256 的签名算法，如果有在判断 token 是否使用 HS256
func (s *SecurityConfig) verifyBearerToken(ctx context.Context, tokenString string) (auth.IDTokenClaims, error) {
	var idToken auth.IDTokenClaims

	// 用户提交的 token 是否为 HS256 签名
	hasHS256Alg := false

	// HS256 仅做该签名算法验证
	hs256Verify := func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() == "HS256" {
			hasHS256Alg = true

			claims, ok := token.Claims.(*auth.IDTokenClaims)
			if ok {
				// 根据 sub 获取作为 username 获取对应的 password 作为 token 的签名验证
				f, b := s.foundUserID(claims.GetMustUserID())
				if f {
					eff := basicAuthEffectivePasswordHash(b)
					if eff == "" {
						return nil, fmt.Errorf("not found key")
					}
					return []byte(eff), nil
				}

				return nil, fmt.Errorf("not found key")
			}
		}

		return nil, nil
	}

	// 仅在服务端配置支持 HS256 算法时才执行
	if s.supportedHS256Alg() {
		token, err := jwt.ParseWithClaims(tokenString, &idToken, hs256Verify)
		if hasHS256Alg && err != nil {
			if s.Authentication.OIDCProvider.Config == nil {
				return idToken, err
			}

			// 继续判断错误类型，忽略 token 过期等
			switch {
			case errors.Is(err, jwt.ErrTokenExpired):
				if s.Authentication.OIDCProvider.Config.SkipExpiryCheck {
					return idToken, nil
				}
			default:
				return idToken, err
			}
		}

		if hasHS256Alg {
			if token == nil || !token.Valid {
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

// initAuthClient 用于初始化 opa 客户端
func (s *SecurityConfig) initAuthClient(ctx context.Context, logger *logrus.Entry, pkgName string, regoBody, dataBody []byte) error {
	ac := &auth.Config{
		PackageName: pkgName,
	}
	if *s.Authorization.OPANative.Enabled {
		ac.OPARego = &auth.OPARegoConfig{
			RegoBody: regoBody,
			DataBody: dataBody,
		}
	}
	if *s.Authorization.OPAExternal.Enabled {
		ac.OPASDK = &auth.OPASDKConfig{
			Config: s.Authorization.OPAExternal.Config,
		}
	}
	if *s.Authorization.OPAEnvoyPlugin.Enabled {
		ac.OPAEnvoy = &auth.OPAEnvoyPluginConfig{
			GRPCAddress: s.Authorization.OPAEnvoyPlugin.Service.GRPCAddress,
		}
	}

	cl, err := auth.NewClient(ctx, ac)
	if err != nil {
		return err
	}
	s.authClient = cl

	s.authClient.WithLoggerOption(logger)

	return nil
}

// policyAllow 用于以下三个权限验证： opa_native、opa_external、opa_envoy_plugin
// 如果同时配置并启动以上多个权限策略，则必须所有允许通过才可
func (s *SecurityConfig) policyAllow(ctx context.Context) (bool, error) {
	// 如果均未开启鉴权，则默认允许通过
	if *s.Authorization.OPANative.Enabled == false &&
		*s.Authorization.OPAExternal.Enabled == false &&
		*s.Authorization.OPAEnvoyPlugin.Enabled == false {
		return true, nil
	}

	ok, err := s.authClient.Allow(ctx)
	if ok && err == nil {
		return true, nil
	}

	return false, err
}

// injectAuthHeader 用于注入认证鉴权信息
func (s *SecurityConfig) injectAuthHTTPHeader(ctx context.Context, req *http.Request) context.Context {
	// 开启任意一个功能，则注入认证鉴权信息
	if *s.Authorization.OPANative.Enabled ||
		*s.Authorization.OPAExternal.Enabled ||
		*s.Authorization.OPAEnvoyPlugin.Enabled {

		return s.authClient.AuthMetadata(ctx, req)
	}

	return ctx
}

// addHTTPHandler 植入认证鉴权
func (s *SecurityConfig) addHTTPHandler(handler http.Handler) http.Handler {
	if s == nil || s.Enable == false {
		return handler
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.TODO()
		ctx = s.injectAuthHTTPHeader(ctx, r)

		ok, err := s.policyAllow(ctx)
		if err != nil || !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		handler.ServeHTTP(w, r)
	})
}

func (s *SecurityConfig) addHTTPHandlerFunc(handler http.HandlerFunc) http.Handler {
	return s.addHTTPHandler(handler)
}

// VerifyHTTPRequest 在 HTTP 层验证请求的身份认证（Basic Auth / Bearer Token）。
// 若 Security 未启用则直接放行；验证成功返回 nil，失败返回 error。
// 该方法签名满足 mcp.AuthFunc（func(*http.Request) error），可直接作为 MCP 认证回调使用。
func (s *SecurityConfig) VerifyHTTPRequest(r *http.Request) error {
	if s == nil || !s.Enable {
		return nil
	}

	if s.Authentication == nil {
		return fmt.Errorf("authentication not configured")
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return fmt.Errorf("missing Authorization header")
	}

	// 尝试 Basic Auth 验证
	if strings.HasPrefix(authHeader, "Basic ") && len(s.Authentication.HTTPUsers) > 0 {
		basicToken := strings.TrimPrefix(authHeader, "Basic ")
		payload, err := base64.StdEncoding.DecodeString(basicToken)
		if err != nil {
			return fmt.Errorf("invalid basic auth encoding: %w", err)
		}

		tmps := strings.SplitN(string(payload), ":", 2)
		if len(tmps) != 2 {
			return fmt.Errorf("invalid basic auth format")
		}

		for _, v := range s.Authentication.HTTPUsers {
			if v == nil {
				continue
			}
			if v.Username == tmps[0] {
				pwTrim := strings.TrimSpace(v.Password)
				okAuth := pwTrim != "" && pwTrim == tmps[1]
				if !okAuth {
					eff := basicAuthEffectivePasswordHash(v)
					if eff != "" {
						h := sha256.New()
						h.Write([]byte(tmps[1]))
						userHash := hex.EncodeToString(h.Sum(nil))
						okAuth = eff == userHash
					}
				}
				if okAuth {
					return nil
				}
			}
		}
		return fmt.Errorf("invalid basic auth credentials")
	}

	// 尝试 Bearer Token 验证
	if strings.HasPrefix(authHeader, "Bearer ") && s.Authentication.OIDCProvider != nil {
		bearerToken := strings.TrimPrefix(authHeader, "Bearer ")
		if bearerToken == "" {
			return fmt.Errorf("empty bearer token")
		}

		ctx := context.TODO()
		_, err := s.verifyBearerToken(ctx, bearerToken)
		if err != nil {
			return fmt.Errorf("invalid bearer token: %w", err)
		}
		return nil
	}

	return fmt.Errorf("unauthorized")
}
