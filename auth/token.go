package auth

import (
	"crypto/rsa"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-kit/pkg/crypto"
)

// CommonClaims 是 ID Token 和 Access Token 共用的基础声明。
type CommonClaims struct {
	jwt.RegisteredClaims

	// --- OIDC Standard Claims（OIDC Core §5.1）---
	// End-User 基础身份声明。是否包含在 Token 中由签发方及请求的 scope/claims 决定。
	// 框架签发的 Access Token 仅承载认证授权所需信息，手机号等用户资料由 userinfo 返回。

	// Email 用户邮箱。
	Email string `json:"email,omitempty"`
	// EmailVerified 邮箱是否已验证。
	EmailVerified bool `json:"email_verified,omitempty"`
	// Name 用户全名，展示用。
	Name string `json:"name,omitempty"`
	// PreferredUsername OIDC 标准用户名。新 token 使用该字段，不再签发自定义 username。
	PreferredUsername string `json:"preferred_username,omitempty"`
	// Nickname 昵称。
	Nickname string `json:"nickname,omitempty"`

	// --- 框架自定义扩展（非 OIDC 标准）---

	// Tenant 租户标识，对应 lion_tenants 中 code 编码。
	Tenant string `json:"tenant,omitempty"`
	// Groups 是可选的用户组编码列表，对应 lion_groups.code。
	// 仅在客户端明确需要组映射时签发。
	Groups []string `json:"groups,omitempty"`
	// Roles 是用户在当前 tenant 下的可选角色编码列表，
	// 对应 lion_roles.code。
	// 仅在客户端明确需要角色映射时签发。
	Roles []string `json:"roles,omitempty"`

	// FederatedClaims 联邦身份声明，如 {"connector_id":"..."}。预留未使用。
	FederatedClaims map[string]string `json:"federated_claims,omitempty"`
	// Deprecated: 历史应用标识字段。
	// 新签发的 ID Token 使用 azp，新签发的 Access Token 使用 client_id。
	// 仅用于兼容解析旧 Token，禁止在新 Token 中签发。
	Appid string `json:"appid,omitempty"`
	// Deprecated: 历史自定义用户名字段。
	// Username 历史自定义字段，仅用于解析旧 token，禁止新 token 签发。
	Username string `json:"username,omitempty"`
}

// EffectiveRoles returns the role codes used for authorization.
// Roles are the only authorization source. Groups describe identity membership
// and are never interpreted as roles, including when the roles claim is absent.
func EffectiveRoles(claims AccessTokenClaims) []string {
	return normalizeRoleCodes(claims.Roles)
}

func normalizeRoleCodes(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}

	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

// IDTokenClaims 仅描述 OIDC ID Token 声明。
// 当前 social_users.go 使用本结构体承载已由 OIDC verifier 验证的外部 Provider id_token；
// 框架 access token 使用 AccessTokenClaims。
// 参考：OIDC Core §2 / §5.1，RFC 7519 §4.1。
type IDTokenClaims struct {
	CommonClaims

	// --- OIDC ID Token 专有声明（OIDC Core §2）---
	// PhoneNumber 是外部 OIDC Provider 可能在 id_token 中返回的可选 E.164 电话号码，
	// 仅用于解析外部 Provider 声明；框架签发的 Access Token 不包含该字段。
	PhoneNumber string `json:"phone_number,omitempty"`
	// PhoneNumberVerified 表示外部 OIDC Provider 已验证 PhoneNumber。
	// 只有该值为 true 时，手机号才可用于已验证标识自动关联。
	PhoneNumberVerified bool `json:"phone_number_verified,omitempty"`

	// Nonce 防重放随机值，由客户端在认证请求中下发并回显。
	Nonce string `json:"nonce,omitempty"`
	// AuthorizedParty 授权方 client_id，语义等价于 Appid。
	AuthorizedParty string `json:"azp,omitempty"`
	// 用户原始认证发生时间。
	AuthTime *jwt.NumericDate `json:"auth_time,omitempty"`
	// ACR 认证上下文等级（Authentication Context Class Reference）。
	ACR string `json:"acr,omitempty"`
	// AMR 认证方式列表（Authentication Methods References），如 ["pwd","otp"]。
	AMR []string `json:"amr,omitempty"`
	// AtHash Access Token 哈希，用于与 access_token 绑定校验。
	AtHash string `json:"at_hash,omitempty"`
	// CHash Authorization Code 哈希，用于与 code 绑定校验。
	CHash string `json:"c_hash,omitempty"`
}

// AccessTokenClaims 仅用于 OAuth 2.0 JWT Access Token。
//
// 它描述资源服务器进行 API 授权所需的客户端、授权范围、
// 租户、角色和用户组等声明。
//
// 参考：RFC 9068、RFC 7519。
type AccessTokenClaims struct {
	CommonClaims

	// --- OAuth2 Access Token 专有声明（RFC 6749 §1.4）---

	// ClientID 是获得该 Access Token 的 OAuth 2.0 客户端标识。
	// 按 RFC 9068 Profile 签发时必须设置。
	ClientID string `json:"client_id,omitempty"`
	// Scope 是本 Access Token 获得授权的 OAuth 2.0 scope 集合。
	// 按 RFC 9068，存在 scope 时编码为空格分隔的字符串。
	Scope string `json:"scope,omitempty"`
}

// ParseIDTokenClaims 解析 token 载荷到 IDTokenClaims，不校验签名。
// 适用于读取已信任来源的 token 声明；如需校验签名请使用 cfg.SecurityConfig.verifyBearerToken。
// [未使用] 当前无调用方；OIDC 流程使用内联 jwt.ParseWithClaims。
func ParseIDTokenClaims(token string) (*IDTokenClaims, error) {
	var claims IDTokenClaims

	_, _, err := jwt.NewParser().ParseUnverified(token, &claims)

	return &claims, err
}

// --- CommonClaims 方法 ---
// 以下 setter 与 GetMustUserID 仅触碰 CommonClaims（或其内嵌 RegisteredClaims）的字段，
// 故定义在 *CommonClaims 上，经嵌入提升后由 IDTokenClaims 与 AccessTokenClaims 共用。

func (c *CommonClaims) SetSubject(subject string) *CommonClaims {
	c.Subject = subject
	return c
}

func (c *CommonClaims) SetExpiresAt(expiresIn int64) *CommonClaims {
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Duration(expiresIn) * time.Second))
	return c
}

// SetEmail 设置真实用户邮箱。空值保持为空，且不会生成占位邮箱。
func (c *CommonClaims) SetEmail(email string) *CommonClaims {
	c.Email = strings.TrimSpace(email)
	if c.Email == "" {
		c.EmailVerified = false
	}
	return c
}

func (c *CommonClaims) SetGroups(groups []string) *CommonClaims {
	c.Groups = groups
	return c
}

func (c *CommonClaims) SetRoles(roles []string) *CommonClaims {
	c.Roles = roles
	return c
}

// GetPreferredUsername 返回 OIDC 标准用户名，并兼容读取历史 username claim。
func (c *CommonClaims) GetPreferredUsername() string {
	if username := strings.TrimSpace(c.PreferredUsername); username != "" {
		return username
	}
	return strings.TrimSpace(c.Username)
}

func (c *CommonClaims) GetMustUserID() int64 {
	userID, err := strconv.ParseInt(c.Subject, 10, 64)
	if err != nil {
		if c.Subject == "" {
			return 0
		}

		username := c.GetPreferredUsername()
		if username == "" {
			username = c.Subject
		}

		// 如果为 lion_users 中用户登录的，则 "subject" 必须为 "user_id"
		// 如果为本地配置文件用户登录的，则 "subject" 有可能为 "username"
		return crypto.Username2UserID(username)
	}

	return userID
}

// --- JWT 签名（共享实现）---
//
// 签名必须序列化具体类型（IDTokenClaims / AccessTokenClaims）的全部字段，
// 因此签名为包级函数、接收 jwt.Claims，由各具体类型的 GetAccessToken 薄包装传入自身。
// 切勿将签名定义为 *CommonClaims 的方法：那样 jwt.NewWithClaims 只会序列化 CommonClaims，
// 丢失 IDToken / AccessToken 的专有声明（nonce、azp、client_id、scope 等）。

func signHS256(claims jwt.Claims, signKey, typ string) (string, error) {
	key := crypto.SHA256([]byte(signKey))
	return signHS256Key(claims, []byte(key), typ)
}

func signHS256Key(claims jwt.Claims, signKey []byte, typ string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["typ"] = typ
	return token.SignedString(signKey)
}

// SignAccessToken 以 HS256 签名生成 Access Token，使用 at+jwt 类型。
// Deprecated: new issuers should use SignAccessTokenHMACKey with explicit key bytes.
// Passing an already-derived password hash to this string API derives it again.
func SignAccessToken(claims jwt.Claims, signKey string) (string, error) {
	return signHS256(claims, signKey, "at+jwt")
}

// SignAccessTokenHMACKey signs an Access Token with an already-derived HMAC
// key. It exists for the static-user profile, whose historical key semantics
// use PasswordHash bytes directly.
func SignAccessTokenHMACKey(claims jwt.Claims, signKey []byte) (string, error) {
	return signHS256Key(claims, signKey, "at+jwt")
}

// SignIDToken 以 HS256 签名生成 ID Token，使用 JWT 类型。
func SignIDToken(claims jwt.Claims, signKey string) (string, error) {
	return signHS256(claims, signKey, "JWT")
}

func signRS256(claims jwt.Claims, privateKey *rsa.PrivateKey, kid, typ string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["typ"] = typ
	if kid != "" {
		token.Header["kid"] = kid
	}
	return token.SignedString(privateKey)
}

// SignAccessTokenRSA 以 RS256 签名生成 Access Token，kid 非空时写入 header。
func SignAccessTokenRSA(claims jwt.Claims, privateKey *rsa.PrivateKey, kid string) (string, error) {
	return signRS256(claims, privateKey, kid, "at+jwt")
}

// SignIDTokenRSA 以 RS256 签名生成 ID Token，kid 非空时写入 header。
func SignIDTokenRSA(claims jwt.Claims, privateKey *rsa.PrivateKey, kid string) (string, error) {
	return signRS256(claims, privateKey, kid, "JWT")
}

// --- 具体类型签名包装 ---
// 保留方法式 API（x.GetAccessToken(key)），内部委托给共享签名函数，
// 传入具体类型自身以保证完整序列化。

// GetAccessToken 以 HS256 签名生成 access token JWT。
// Deprecated: IDTokenClaims 不应用于新 access token；仅为兼容旧调用保留。
func (i *IDTokenClaims) GetAccessToken(signKey string) (string, error) {
	return SignIDToken(i, signKey)
}

// GetAccessTokenRSA 以 RS256 签名生成 access token JWT，kid 非空时写入 header。
// Deprecated: IDTokenClaims 不应用于新 access token；仅为兼容旧调用保留。
func (i *IDTokenClaims) GetAccessTokenRSA(privateKey *rsa.PrivateKey, kid string) (string, error) {
	return SignIDTokenRSA(i, privateKey, kid)
}

// GetAccessToken 以 HS256 签名生成 access token JWT。
// Deprecated: use SignAccessTokenHMACKey with explicit key bytes for new issuers.
func (a *AccessTokenClaims) GetAccessToken(signKey string) (string, error) {
	return SignAccessToken(a, signKey)
}

// GetAccessTokenRSA 以 RS256 签名生成 access token JWT，kid 非空时写入 header。
func (a *AccessTokenClaims) GetAccessTokenRSA(privateKey *rsa.PrivateKey, kid string) (string, error) {
	return SignAccessTokenRSA(a, privateKey, kid)
}
