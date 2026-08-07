package admin

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/credentials"
	"github.com/grpc-kit/pkg/lion/users"
)

// AccessTokenInput contains only data needed to build a JWT Access Token.
// Database access, key selection, time and identifier generation stay outside
// BuildAccessTokenClaims so the constructor remains deterministic.
type AccessTokenInput struct {
	Subject           string
	PreferredUsername string
	Email             string
	EmailVerified     bool
	Roles             []string
	Groups            []string
	Tenant            string
	ClientID          string
	Scope             string
	TTL               time.Duration
	IssuedAt          time.Time
	JWTID             string
}

// AccessTokenIssuanceContext survives an MFA challenge. It intentionally does
// not contain tokens, credentials, signing keys, or authorization snapshots.
type AccessTokenIssuanceContext struct {
	ClientID string
	Scope    string
	// Tenant/Roles/Groups 为令牌声明的最终值：留空（""/nil）则对应声明不写入令牌
	// （json omitempty）。issuer 不再隐式回退，调用方须显式填入期望值——登录路径填
	// 静态用户自身配置，CreateAuthToken 按授权决策填入（留空即省略）。
	Tenant string
	Roles  []string
	Groups []string
	// PreferredUsername/Email 为令牌身份展示字段的覆盖值：非空则覆盖静态用户/DB profile
	// 自身值（仅 superadmin 可设置）。留空时，OmitIdentityFields=true（superadmin 签发）
	// 则不写入令牌（不回退自身）；OmitIdentityFields=false（登录/MFA/非 superadmin）则
	// 回退到静态用户/DB profile 自身值。subject 由签发路径决定（委托签发时为目标 user_id）。
	PreferredUsername string
	Email             string
	// EmailVerified 仅在 Email 非空时写入令牌（superadmin 可选）；其余签发路径取静态
	// 用户/DB profile 自身值或固定 false。
	EmailVerified bool
	// OmitIdentityFields 为 true 时，PreferredUsername/Email 留空即不写入令牌（不回退
	// 到调用方自身值）；仅 CreateAuthToken superadmin 路径置 true，其余签发路径保持 false。
	OmitIdentityFields bool
	TTL               time.Duration
}

type accessTokenUserProfile struct {
	UserID        int
	Username      string
	Email         string
	EmailVerified bool
}

func (a *KnownAdminAPI) newAccessTokenIssuanceContext(clientID, scope string, ttl time.Duration) (AccessTokenIssuanceContext, error) {
	if a == nil || a.config == nil {
		return AccessTokenIssuanceContext{}, fmt.Errorf("admin access token configuration is required")
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		clientID = strings.TrimSpace(a.config.clientID)
	}
	if clientID == "" {
		return AccessTokenIssuanceContext{}, fmt.Errorf("access token client_id is required")
	}
	if ttl <= 0 {
		return AccessTokenIssuanceContext{}, fmt.Errorf("access token TTL must be positive")
	}
	return AccessTokenIssuanceContext{
		ClientID: clientID,
		Scope:    strings.Join(normalizeClaimValues(strings.Fields(scope)), " "),
		// Tenant/Roles/Groups 默认留空：调用方按需显式覆盖（登录填静态用户配置，
		// CreateAuthToken 按授权决策填入），留空则不写入对应声明。
		TTL: ttl,
	}, nil
}

// BuildAccessTokenClaims constructs claims without querying a database,
// selecting a key, signing, or generating implicit identifiers.
func BuildAccessTokenClaims(input AccessTokenInput) (*auth.AccessTokenClaims, error) {
	input.Subject = strings.TrimSpace(input.Subject)
	input.PreferredUsername = strings.TrimSpace(input.PreferredUsername)
	input.Email = strings.TrimSpace(input.Email)
	input.ClientID = strings.TrimSpace(input.ClientID)
	input.JWTID = strings.TrimSpace(input.JWTID)
	if input.Subject == "" {
		return nil, fmt.Errorf("access token subject is required")
	}
	if input.ClientID == "" {
		return nil, fmt.Errorf("access token client_id is required")
	}
	if input.TTL <= 0 {
		return nil, fmt.Errorf("access token TTL must be positive")
	}
	if input.IssuedAt.IsZero() {
		return nil, fmt.Errorf("access token issued_at is required")
	}
	if input.JWTID == "" {
		return nil, fmt.Errorf("access token jti is required")
	}

	claims := &auth.AccessTokenClaims{
		CommonClaims: auth.CommonClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				Subject:   input.Subject,
				ExpiresAt: jwt.NewNumericDate(input.IssuedAt.Add(input.TTL)),
				IssuedAt:  jwt.NewNumericDate(input.IssuedAt),
				ID:        input.JWTID,
			},
			PreferredUsername: input.PreferredUsername,
			// Tenant/Roles/Groups 留空即省略（json omitempty）：仅在调用方明确提供时
			// 写入对应声明，不再隐式回退到 "default" 或静态用户配置。
			Tenant: strings.TrimSpace(input.Tenant),
			Roles:  normalizeClaimValues(input.Roles),
			Groups: normalizeClaimValues(input.Groups),
		},
		ClientID: input.ClientID,
		Scope:    strings.Join(normalizeClaimValues(strings.Fields(input.Scope)), " "),
	}
	if input.Email != "" {
		claims.Email = input.Email
		claims.EmailVerified = input.EmailVerified
	}
	return claims, nil
}

func normalizeClaimValues(values []string) []string {
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
	sort.Strings(result)
	return result
}

type accessTokenIssuer struct {
	now      func() time.Time
	newJWTID func() string
}

func newAccessTokenIssuer() *accessTokenIssuer {
	return &accessTokenIssuer{
		now:      time.Now,
		newJWTID: uuid.NewString,
	}
}

func (i *accessTokenIssuer) build(input AccessTokenInput) (*auth.AccessTokenClaims, error) {
	if input.IssuedAt.IsZero() {
		input.IssuedAt = i.now()
	}
	if strings.TrimSpace(input.JWTID) == "" {
		input.JWTID = i.newJWTID()
	}
	return BuildAccessTokenClaims(input)
}

func (i *accessTokenIssuer) issueRSA(input AccessTokenInput, privateKey *rsa.PrivateKey, kid string) (string, error) {
	claims, err := i.build(input)
	if err != nil {
		return "", err
	}
	return auth.SignAccessTokenRSA(claims, privateKey, kid)
}

func (i *accessTokenIssuer) issueStaticHS256(input AccessTokenInput, key []byte) (string, error) {
	claims, err := i.build(input)
	if err != nil {
		return "", err
	}
	return auth.SignAccessTokenHMACKey(claims, key)
}

func loadAccessTokenUserProfile(ctx context.Context, db *lion.Client, aesKey []byte, userID int) (accessTokenUserProfile, error) {
	row, err := db.Users.Query().
		Select(
			users.FieldID,
			users.FieldUsername,
			users.FieldEmailEncrypted,
			users.FieldEmailVerified,
		).
		Where(
			users.IDEQ(userID),
			users.UserStatusEQ(int(adminv1.User_ACTIVE)),
			users.DeletedAtIsNil(),
		).
		Only(ctx)
	if err != nil {
		return accessTokenUserProfile{}, fmt.Errorf("load active access token user profile: %w", err)
	}
	profile := accessTokenUserProfile{
		UserID:        row.ID,
		Username:      row.Username,
		EmailVerified: row.EmailVerified,
	}
	if len(row.EmailEncrypted) > 0 {
		email, err := crypto.DecryptAES(aesKey, row.EmailEncrypted)
		if err != nil {
			return accessTokenUserProfile{}, fmt.Errorf("decrypt access token email: %w", err)
		}
		profile.Email = strings.TrimSpace(string(email))
	}
	if profile.Email == "" {
		profile.EmailVerified = false
	}
	return profile, nil
}

func accessTokenInputFromProfile(profile accessTokenUserProfile, issuance AccessTokenIssuanceContext, roles, groups []string) AccessTokenInput {
	// 身份展示字段：OmitIdentityFields（superadmin 签发）时直接采用 issuance 值，留空即
	// 不写入令牌；否则 issuance 非空覆盖、留空回退 DB profile 自身值。
	preferredUsername := profile.Username
	email := profile.Email
	emailVerified := profile.EmailVerified
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
	return AccessTokenInput{
		Subject:           strconv.Itoa(profile.UserID),
		PreferredUsername: preferredUsername,
		Email:             email,
		EmailVerified:     emailVerified,
		Roles:             roles,
		Groups:            groups,
		Tenant:            issuance.Tenant,
		ClientID:          issuance.ClientID,
		Scope:             issuance.Scope,
		TTL:               issuance.TTL,
	}
}

func loadAccessTokenRSAKey(ctx context.Context, db *lion.Client, aesKey []byte) (*rsa.PrivateKey, string, error) {
	now := time.Now()
	row, err := db.Credentials.Query().
		Select(credentials.FieldPrivateKeyEncrypted, credentials.FieldCode).
		Where(
			credentials.CredentialTypeEQ(int(adminv1.Credential_KEY_PAIR)),
			credentials.CredentialAlgorithmEQ(int(adminv1.Credential_RSA)),
			credentials.CredentialUsageEQ(int(adminv1.Credential_JWKS)),
			credentials.CredentialVisibilityEQ(int(adminv1.Visibility_VISIBILITY_RESTRICTED)),
			credentials.CredentialStatusEQ(int(adminv1.Credential_ACTIVE)),
			credentials.CredentialSourceEQ(int(adminv1.Credential_SYSTEM)),
			credentials.DeletedAtIsNil(),
			credentials.Or(credentials.NotBeforeIsNil(), credentials.NotBeforeLTE(now)),
			credentials.Or(credentials.ExpiresAtIsNil(), credentials.ExpiresAtGT(now)),
		).
		Order(credentials.ByID()).
		First(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("load access token signing key: %w", err)
	}
	derBytes, err := crypto.DecryptAES(aesKey, row.PrivateKeyEncrypted)
	if err != nil {
		return nil, "", fmt.Errorf("decrypt access token signing key: %w", err)
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse access token signing key: %w", err)
	}
	return privateKey, row.Code, nil
}
