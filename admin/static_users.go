package admin

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/grpc-kit/pkg/auth"
)

// StaticUser 本地配置的静态用户
type StaticUser struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	Email        string   `json:"email"`
	Groups       []string `json:"groups"`
}

// GetAccessToken 获取或生成 jwt token
func (s StaticUser) GetAccessToken(expiresIn int32) (string, error) {
	// TODO; 生成 jwt token 需要考虑不通用户级别生成 token 的最长有效时间

	claims := auth.IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   s.Username,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expiresIn) * time.Second)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
		Email:           fmt.Sprintf("%s@localhost", s.Username),
		EmailVerified:   true,
		Groups:          s.Groups,
		FederatedClaims: nil,
		Tenant:          "default",
	}

	ss, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(s.PasswordHash))
	if err != nil {
		return ss, err
	}

	return ss, nil
}

type StaticUsers []*StaticUser

// Valid 验证用户密码是否正确
func (s *StaticUsers) Valid(username, passwordHash string) (*StaticUser, bool) {
	for _, user := range *s {
		if user.Username == username && user.PasswordHash == passwordHash {
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
