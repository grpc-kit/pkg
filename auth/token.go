package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/grpc-kit/pkg/crypto"
)

// IDTokenClaims 用于框架jwt的数据结构
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Email           string            `json:"email"`
	EmailVerified   bool              `json:"email_verified"`
	Groups          []string          `json:"groups"`
	FederatedClaims map[string]string `json:"federated_claims"`
	Tenant          string            `json:"tenant"`
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
