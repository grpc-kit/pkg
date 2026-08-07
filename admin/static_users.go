package admin

import (
	"strconv"
	"strings"
	"time"

	"github.com/grpc-kit/pkg/crypto"
)

// StaticUser 本地配置的静态用户
type StaticUser struct {
	UserID       int64    `json:"user_id"`
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	Email        string   `json:"email"`
	Groups       []string `json:"groups"`
	Roles        []string `json:"roles,omitempty"`
	Tenant       string   `json:"tenant"`
}

// GetAccessToken 获取或生成 jwt token。第二个参数是标准 client_id；
// 历史调用方可保持原调用形态，但新 token 不再写入 appid claim。
func (s StaticUser) GetAccessToken(expiresIn int32, clientID string) (string, error) {
	return s.issueAccessToken(AccessTokenIssuanceContext{
		ClientID: clientID,
		TTL:      time.Duration(expiresIn) * time.Second,
	})
}

func (s StaticUser) issueAccessToken(issuance AccessTokenIssuanceContext) (string, error) {
	// TODO; 生成 jwt token 需要考虑不通用户级别生成 token 的最长有效时间

	// tenant/roles/groups 完全由 issuance 决定：留空（""/nil）则对应声明不写入令牌
	// （json omitempty）。issuer 不再隐式回退——登录路径由调用方显式填入静态用户自身
	// 配置，CreateAuthToken 按授权决策填入（留空即省略）。
	tenant := strings.TrimSpace(issuance.Tenant)
	roles := issuance.Roles
	groups := issuance.Groups

	// 身份展示字段：OmitIdentityFields（superadmin 签发）时直接采用 issuance 值，留空即
	// 不写入令牌；否则 issuance 非空覆盖、留空回退静态用户自身值。
	preferredUsername := s.Username
	email := s.Email
	emailVerified := false
	if issuance.OmitIdentityFields {
		preferredUsername = strings.TrimSpace(issuance.PreferredUsername)
		email = strings.TrimSpace(issuance.Email)
		emailVerified = issuance.EmailVerified
	} else {
		if v := strings.TrimSpace(issuance.PreferredUsername); v != "" {
			preferredUsername = v
		}
		if v := strings.TrimSpace(issuance.Email); v != "" {
			email = v
		}
	}

	userID := s.UserID
	if userID == 0 {
		userID = crypto.Username2UserID(s.Username)
	}

	input := AccessTokenInput{
		Subject:           strconv.FormatInt(userID, 10),
		PreferredUsername: preferredUsername,
		Email:             email,
		EmailVerified:     emailVerified,
		Groups:            groups,
		Roles:             roles,
		Tenant:            tenant,
		ClientID:          issuance.ClientID,
		Scope:             issuance.Scope,
		TTL:               issuance.TTL,
	}
	return newAccessTokenIssuer().issueStaticHS256(input, []byte(s.PasswordHash))
}

type StaticUsers []*StaticUser

// Valid 验证 LOCAL 登录载荷（CreateAuthLoginRequest.password_hash）是否与静态用户匹配。
// 存储为 sha256 十六进制时做字符串相等比较；存储为 bcrypt 时（以 “$2” 开头）用 BcryptCompare，与库表 LOCAL 用户约定一致。
func (s *StaticUsers) Valid(username, passwordHash string) (*StaticUser, bool) {
	for _, user := range *s {
		if user.Username != username {
			continue
		}
		if user.PasswordHash == passwordHash {
			return user, true
		}
		if strings.HasPrefix(user.PasswordHash, "$2") && crypto.BcryptCompare(user.PasswordHash, passwordHash) == nil {
			return user, true
		}
	}

	return nil, false
}

// Find 按 username 反查静态用户（不校验口令）。
// 供已认证调用方重签自身令牌时定位静态用户及其 HS256 签名密钥。
func (s *StaticUsers) Find(username string) (*StaticUser, bool) {
	for _, user := range *s {
		if user.Username == username {
			return user, true
		}
	}
	return nil, false
}

// FindByUserID 按 user_id 查找静态用户（兼容 UserID==0 时用 username 折算 user_id）。
// 供 CreateAuthToken 委托签发按目标 user_id 定位静态用户及其 HS256 签名密钥。
func (s *StaticUsers) FindByUserID(userID int64) (*StaticUser, bool) {
	for _, user := range *s {
		uid := user.UserID
		if uid == 0 {
			uid = crypto.Username2UserID(user.Username)
		}
		if uid == userID {
			return user, true
		}
	}
	return nil, false
}

// Append 添加本地静态用户
func (s *StaticUsers) Append(user *StaticUser) {
	for _, u := range *s {
		if u.Username == user.Username {
			return
		}
	}

	*s = append(*s, user)
}

// Len 返回用户数量
func (s *StaticUsers) Len() int {
	return len(*s)
}
