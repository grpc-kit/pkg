package admin

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/crypto"
)

// StaticUser 本地配置的静态用户
type StaticUser struct {
	UserID       int64    `json:"user_id"`
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	Email        string   `json:"email"`
	Groups       []string `json:"groups"`
	Tenant       string   `json:"tenant"`
}

// GetAccessToken 获取或生成 jwt token
func (s StaticUser) GetAccessToken(expiresIn int32, appid string) (string, error) {
	// TODO; 生成 jwt token 需要考虑不通用户级别生成 token 的最长有效时间

	tenant := "default"
	if s.Tenant != "" {
		tenant = s.Tenant
	}

	userID := s.UserID
	if userID == 0 {
		userID = crypto.Username2UserID(s.Username)
	}

	claims := auth.IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatInt(userID, 10),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expiresIn) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
		Email:           fmt.Sprintf("%s@localhost", s.Username),
		EmailVerified:   true,
		Groups:          s.Groups,
		FederatedClaims: nil,
		Appid:           appid,
		Tenant:          tenant,
		Username:        s.Username,
		Nickname:        s.Username,
	}

	ss, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.PasswordHash))
	if err != nil {
		return ss, err
	}

	return ss, nil
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
