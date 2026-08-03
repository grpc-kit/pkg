package auth

import (
	"crypto/rsa"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-kit/pkg/crypto"
)

// CommonClaims 是 ID Token 和 Access Token 共用的基础声明。
type CommonClaims struct {
	jwt.RegisteredClaims

	// --- OIDC Standard Claims（OIDC Core §5.1）---
	// End-User 信息声明。PhoneNumber 等字段由 userinfo 端点从数据库返回而非 JWT。

	// Email 用户邮箱。
	Email string `json:"email,omitempty"`
	// EmailVerified 邮箱是否已验证。
	EmailVerified bool `json:"email_verified,omitempty"`
	// Name 用户全名，展示用。
	Name string `json:"name,omitempty"`
	// PreferredUsername OIDC 标准用户名；框架使用 Username，此字段仅作 GetMustUserID 回退。
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

	// Deprecated: 历史应用标识字段。
	// FederatedClaims 联邦身份声明，如 {"connector_id":"..."}。预留未使用。
	FederatedClaims map[string]string `json:"federated_claims,omitempty"`
	// Deprecated: 历史应用标识字段。
	// 新签发的 ID Token 使用 azp，新签发的 Access Token 使用 client_id。
	// 仅用于兼容解析旧 Token，禁止在新 Token 中签发。
	Appid string `json:"appid,omitempty"`
	// Deprecated: 历史应用标识字段。
	// Username 事实主用户名字段。GetMustUserID 优先使用，为空时回退到 PreferredUsername。
	Username string `json:"username,omitempty"`
}

// IDTokenClaims 是框架通用 JWT 载荷，同时用于签发 OIDC ID Token 和 OAuth2 Access Token。
// 所有登录路径（static_users / mfa / social_users）均以本结构体构建 access_token。
// social_users.go 通过 jwt.ParseWithClaims 将外部 OIDC Provider 的 id_token 反序列化到本结构体，
// 因此保留 OIDC 标准字段即使框架自身不设置。
// 参考：OIDC Core §2 / §5.1，RFC 7519 §4.1。
type IDTokenClaims struct {
	CommonClaims

	// --- OIDC ID Token 专有声明（OIDC Core §2）---

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

func (i *IDTokenClaims) SetSubject(subject string) *IDTokenClaims {
	i.Subject = subject
	return i
}

func (i *IDTokenClaims) SetExpiresAt(expiresIn int64) *IDTokenClaims {
	i.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Duration(expiresIn) * time.Second))
	return i
}

// SetEmail 设置用户邮箱。当 email 为空时回退到 sub@localhost。
// BUG: 条件应为 email != ""，当前逻辑导致传入非空 email 时不赋值（所有调用方均传入非空值）。
func (i *IDTokenClaims) SetEmail(email string) *IDTokenClaims {
	if email == "" {
		i.Email = fmt.Sprintf("%s@localhost", i.Subject)
		i.EmailVerified = true
	}

	return i
}

func (i *IDTokenClaims) SetGroups(groups []string) *IDTokenClaims {
	i.Groups = groups
	return i
}

// GetAccessToken 以 HS256 签名生成 access token JWT。
func (i *IDTokenClaims) GetAccessToken(signeKey string) (string, error) {
	key := crypto.SHA256([]byte(signeKey))

	ss, err := jwt.NewWithClaims(jwt.SigningMethodHS256, i).SignedString([]byte(key))
	if err != nil {
		return ss, err
	}

	return ss, nil
}

// GetAccessTokenRSA 以 RS256 签名生成 access token JWT，kid 非空时写入 header。
func (i *IDTokenClaims) GetAccessTokenRSA(signeKey *rsa.PrivateKey, kid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, i)
	if kid != "" {
		token.Header["kid"] = kid
	}
	ss, err := token.SignedString(signeKey)
	if err != nil {
		return ss, err
	}

	return ss, nil
}

func (i *IDTokenClaims) GetMustUserID() int64 {
	userID, err := strconv.ParseInt(i.Subject, 10, 64)
	if err != nil {
		if i.Subject == "" {
			return 0
		}

		username := i.Username
		if username == "" {
			// 回退到 OIDC 标准字段 preferred_username
			username = i.PreferredUsername
		}
		if username == "" {
			username = i.Subject
		}

		// 如果为 lion_users 中用户登录的，则 "subject" 必须为 "user_id"
		// 如果为本地配置文件用户登录的，则 "subject" 有可能为 "username"
		return crypto.Username2UserID(username)
	}

	return userID
}
