package auth

import (
	"crypto/rsa"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/grpc-kit/pkg/crypto"
)

// IDTokenClaims 用于框架jwt的数据结构
// 部分参考：https://openid.net/specs/openid-connect-core-1_0.html#IDToken
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	// 注意：在这里 "Groups" 对应平台 "lion_roles" 表中的 "name" 而非 "lion_groups" 内容。
	Groups          []string          `json:"groups,omitempty"`
	FederatedClaims map[string]string `json:"federated_claims,omitempty"`
	Appid           string            `json:"appid,omitempty"`
	Tenant          string            `json:"tenant,omitempty"`
	Username        string            `json:"username,omitempty"`
	Nickname        string            `json:"nickname,omitempty"`
}

// ParseIDTokenClaims 解析 token
func ParseIDTokenClaims(token string) (*IDTokenClaims, error) {
	var ok bool
	var claims IDTokenClaims

	_, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// 从这里获取该token的appid
		claims, ok = token.Claims.(IDTokenClaims)
		if !ok {
			return nil, fmt.Errorf("token invalid not match cfg.id_token")
		}

		return []byte(""), nil
	})

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

// GetAccessToken 获取或生成 jwt token
func (i *IDTokenClaims) GetAccessToken(signeKey string) (string, error) {
	key := crypto.SHA256([]byte(signeKey))

	ss, err := jwt.NewWithClaims(jwt.SigningMethodHS256, i).SignedString([]byte(key))
	if err != nil {
		return ss, err
	}

	return ss, nil
}

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
			username = i.Subject
		}

		// 如果为 lion_users 中用户登录的，则 "subject" 必须为 "user_id"
		// 如果为本地配置文件用户登录的，则 "subject" 有可能为 "username"
		return crypto.Username2UserID(username)
	}

	return userID
}
