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
	Nickname          string
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
	Tenant   string
	TTL      time.Duration
}

type accessTokenUserProfile struct {
	UserID        int
	Username      string
	Nickname      string
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
		Tenant:   "default",
		TTL:      ttl,
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

	tenant := strings.TrimSpace(input.Tenant)
	if tenant == "" {
		tenant = "default"
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
			Nickname:          strings.TrimSpace(input.Nickname),
			Tenant:            tenant,
			Roles:             normalizeClaimValues(input.Roles),
			Groups:            normalizeClaimValues(input.Groups),
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
			users.FieldNickname,
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
		Nickname:      row.Nickname,
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
	return AccessTokenInput{
		Subject:           strconv.Itoa(profile.UserID),
		PreferredUsername: profile.Username,
		Nickname:          profile.Nickname,
		Email:             profile.Email,
		EmailVerified:     profile.EmailVerified,
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
