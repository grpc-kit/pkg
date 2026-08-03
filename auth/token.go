package auth

import (
	"crypto/rsa"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-kit/pkg/crypto"
)

// IDTokenClaims 是框架使用的 JWT 载荷数据结构，同时用于签发和解析 OIDC ID Token
// 与 OAuth2 Access Token（参见 GetAccessToken / GetAccessTokenRSA）。
// 部分参考：https://openid.net/specs/openid-connect-core-1_0.html#IDToken
//
// 虽然结构体以 "IDToken" 命名，但框架所有登录路径（static_users / mfa / social_users）
// 均使用本结构体构建 JWT 并作为 access_token 返回；GetAccessToken(HS256) 和
// GetAccessTokenRSA(RS256) 也以本结构体为载荷。因此本结构体实质是
// ID Token + Access Token 复用的通用 JWT Claims。
//
// 字段分为四组：
//  1. JWT 注册声明：内嵌 jwt.RegisteredClaims（RFC 7519 §4.1），
//     其中 iss/sub/aud/exp/iat 为 ID Token 和 Access Token 共用的必填项。
//  2. OIDC ID Token 专有声明（OIDC Core §2）：nonce/azp/acr/amr/at_hash/c_hash；
//     仅 ID Token 语义使用，当前签发路径（access token）均未设置。
//  3. OIDC Standard Claims（OIDC Core §5.1）：End-User 信息声明；
//     ID Token 和 Access Token 均可携带，当前签发的 access token 仅填充
//     Email/EmailVerified/Name/Nickname，其余字段由 userinfo 端点从数据库返回。
//  4. 框架自定义扩展：groups/federated_claims/appid/tenant/username；
//     非 OIDC 标准，ID Token 和 Access Token 均携带，保留以兼容历史 token。
type IDTokenClaims struct {
	jwt.RegisteredClaims

	// --- OIDC ID Token 专有声明（OIDC Core §2）---
	// 以下字段仅 ID Token 语义使用；当前签发路径（access token）均未设置，预留。

	// Nonce 防重放随机值：仅隐式/混合流程 ID Token 使用，由客户端在认证请求中下发并在此回显。
	Nonce string `json:"nonce,omitempty"`
	// AuthorizedParty 授权方（client_id），ID Token 被签发给的目标客户端。
	// [未使用] 当前从不设置；语义等价于 Appid，二者未统一，待后续迁移。
	AuthorizedParty string `json:"azp,omitempty"`
	// ACR 认证上下文等级（Authentication Context Class Reference），仅 ID Token 使用。
	// 如 "urn:mace:incommon:iap:silver" 或简单等级标识。当前未设置。
	ACR string `json:"acr,omitempty"`
	// AMR 认证方式列表（Authentication Methods References），仅 ID Token 使用。
	// 如 ["pwd","otp"]。当前未设置。
	AMR []string `json:"amr,omitempty"`
	// AtHash Access Token 哈希，仅隐式/混合流程 ID Token 使用，用于与 access_token 绑定校验。当前未设置。
	AtHash string `json:"at_hash,omitempty"`
	// CHash Authorization Code 哈希，仅混合流程 ID Token 使用，用于与 code 绑定校验。当前未设置。
	CHash string `json:"c_hash,omitempty"`

	// --- OIDC Standard Claims（OIDC Core §5.1）---
	// End-User 信息声明，ID Token 和 Access Token 均可携带。
	// 当前签发的 access token 仅填充 Email/EmailVerified/Name/Nickname，
	// 其余字段由 userinfo 端点从数据库返回而非 JWT。

	// Email 用户邮箱。
	Email string `json:"email,omitempty"`
	// EmailVerified 邮箱是否已验证。
	EmailVerified bool `json:"email_verified,omitempty"`
	// Name 用户全名，展示用。
	Name string `json:"name,omitempty"`
	// PreferredUsername 标准的用户名展示字段，与历史字段 Username 等价。
	// [未使用] 当前从不设置；签发代码使用 Username，此字段仅作 GetMustUserID 回退（实际永不命中）。
	PreferredUsername string `json:"preferred_username,omitempty"`
	// Nickname 昵称。
	Nickname string `json:"nickname,omitempty"`
	// PhoneNumber 电话号码（E.164 格式）。userinfo 端点从数据库取值而非 JWT。
	PhoneNumber string `json:"phone_number,omitempty"`
	// PhoneNumberVerified 电话号码是否已验证。userinfo 端点从数据库取值而非 JWT。
	PhoneNumberVerified bool `json:"phone_number_verified,omitempty"`
	// UpdatedAt 用户信息最后更新时间（Unix 秒）。userinfo 端点从数据库取值而非 JWT。
	UpdatedAt *jwt.NumericDate `json:"updated_at,omitempty"`

	// --- 框架自定义扩展（非 OIDC 标准，兼容历史 token）---
	// ID Token 和 Access Token 均携带。

	// Groups 用户所属组。
	// 注意：在这里 "Groups" 对应平台 "lion_roles" 表中的 "name" 而非 "lion_groups" 内容。
	// OIDC 标准未定义 groups 声明，此为业界（Azure AD/Keycloak/Dex）通用扩展。
	Groups []string `json:"groups,omitempty"`
	// FederatedClaims 联邦身份声明（如 {"connector_id":"..."}）。
	// [未使用] 从未赋实际值，预留。
	FederatedClaims map[string]string `json:"federated_claims,omitempty"`
	// Appid 应用 ID，对应 OIDC 标准的 azp（AuthorizedParty）。
	// [仅静态用户] 仅 static_users.go 设置，无读取方；语义等价于 azp，待后续统一。
	Appid string `json:"appid,omitempty"`
	// Tenant 租户标识，对应 Azure AD 的 tid。
	// [仅静态用户] 仅 static_users.go 设置；DB 驱动登录路径不设置；GRN 多租户设计依赖此字段但尚未贯通。
	Tenant string `json:"tenant,omitempty"`
	// Username 历史用户名字段，非 OIDC 标准。
	// [实际使用] 事实主用户名字段；所有签发/读取路径均使用此字段，而非 PreferredUsername。
	// 为兼容旧 token 保留，GetMustUserID 会回退到 PreferredUsername。
	Username string `json:"username,omitempty"`
}

// ParseIDTokenClaims 解析（仅解码）token 载荷到 IDTokenClaims。
//
// 注意：本函数仅做载荷反序列化，不校验签名，适用于读取已信任来源 token 声明内容的场景
// （如解析外部 OIDC Provider 下发的 id_token 字段）；如需校验签名请使用
// cfg.SecurityConfig.verifyBearerToken。
//
// [未使用] 本函数当前无调用方；OIDC 流程（social_users.go）使用内联 jwt.ParseWithClaims。
//
// 使用 jwt.Parser.ParseUnverified 将载荷反序列化到 *IDTokenClaims：
// 旧实现使用 jwt.Parse（默认 MapClaims）后再做 token.Claims.(IDTokenClaims) 类型断言，
// 载荷会被解析成 map[string]any，断言必然失败、claims 永远为空。
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

// GetAccessToken 使用 IDTokenClaims 作为 access token 载荷，以 HS256 签名生成 JWT。
// 体现了本结构体 ID Token 与 Access Token 复用的设计。
func (i *IDTokenClaims) GetAccessToken(signeKey string) (string, error) {
	key := crypto.SHA256([]byte(signeKey))

	ss, err := jwt.NewWithClaims(jwt.SigningMethodHS256, i).SignedString([]byte(key))
	if err != nil {
		return ss, err
	}

	return ss, nil
}

// GetAccessTokenRSA 使用 IDTokenClaims 作为 access token 载荷，以 RS256 签名生成 JWT。
// 体现了本结构体 ID Token 与 Access Token 复用的设计。
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
