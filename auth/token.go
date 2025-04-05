package auth

import "github.com/golang-jwt/jwt/v4"

// IDTokenClaims 用于框架jwt的数据结构
type IDTokenClaims struct {
	jwt.RegisteredClaims
	Email           string            `json:"email"`
	EmailVerified   bool              `json:"email_verified"`
	Groups          []string          `json:"groups"`
	FederatedClaims map[string]string `json:"federated_claims"`
	Tenant          string            `json:"tenant"`
}
