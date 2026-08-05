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
		Tenant:   "default",
		TTL:      time.Duration(expiresIn) * time.Second,
	})
}

func (s StaticUser) issueAccessToken(issuance AccessTokenIssuanceContext) (string, error) {
	// TODO; 生成 jwt token 需要考虑不通用户级别生成 token 的最长有效时间

	tenant := "default"
	if s.Tenant != "" {
		tenant = s.Tenant
	}

	userID := s.UserID
	if userID == 0 {
		userID = crypto.Username2UserID(s.Username)
	}

	issuance.Tenant = tenant
	input := AccessTokenInput{
		Subject:           strconv.FormatInt(userID, 10),
		PreferredUsername: s.Username,
		Nickname:          s.Username,
		Email:             s.Email,
		EmailVerified:     false,
		Groups:            s.Groups,
		Roles:             s.Roles,
		Tenant:            issuance.Tenant,
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
