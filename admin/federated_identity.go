package admin

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/oauth2clients"
)

// FederatedLoginAuthorization 表示服务端已批准处理的联邦登录请求。
// 同进程调用方须先验证浏览器流程，并绑定上游 state 和所选认证提供方。
// ExpiresAt 为原始流程截止时间，回调或 MFA 不得延长。
// 此参数不代替向下游发放授权码或 Token 前的用户同意。
type FederatedLoginAuthorization struct {
	ClientID    string
	RedirectURI string
	Scope       string
	ExpiresAt   time.Time
}

type federatedLoginAuthorizationKey struct{}

// ContextWithFederatedLoginAuthorization 为本次同进程登录保存授权参数的值副本。
// 调用方须先验证浏览器授权流程、上游 state 与所选认证提供方的绑定，
// 并保留下游用户同意步骤；不得从未验证的请求或 metadata 自动注入。
// 返回的 context 仅用于本次 CreateAuthLogin 或 GetAuthCallback 调用，
// 不应保存到服务对象或供无关请求复用。
func ContextWithFederatedLoginAuthorization(parent context.Context, authorization FederatedLoginAuthorization) context.Context {
	return context.WithValue(parent, federatedLoginAuthorizationKey{}, authorization)
}

func federatedLoginAuthorizationFromContext(ctx context.Context) *FederatedLoginAuthorization {
	authorization, ok := ctx.Value(federatedLoginAuthorizationKey{}).(FederatedLoginAuthorization)
	if !ok {
		return nil
	}
	return &authorization
}

// federatedSource 仅在本次认证成功后及后续 MFA 期间保存在内存中，
// 不单独序列化，也不写入 Token 上下文存储。
type federatedSource struct {
	userID, providerID             int
	connectorID, subject, username string
}

func (s *socialUsers) captureFederatedSource(userID int, subject, username string) {
	if !auth.HasFederatedScope(s.issuanceContext.Scope) || s.AuthProvider.ProviderType == int(adminv1.AuthProvider_LOCAL) {
		return
	}
	if !auth.ValidFederatedUsername(username) {
		username = ""
	}
	s.authenticationSource = &federatedSource{userID: userID, providerID: s.AuthProvider.ID,
		connectorID: s.AuthProvider.Code, subject: subject, username: username}
}

func canonicalScope(scope string) string {
	return strings.Join(normalizeClaimValues(strings.Fields(scope)), " ")
}

func (a *KnownAdminAPI) federatedDB(ctx context.Context) (*lion.Client, error) {
	if a == nil || a.config == nil || a.config.db == nil {
		return nil, errs.FailedPrecondition(ctx).WithMessage("OAuth2 client storage is required")
	}
	return a.config.db, nil
}

func validateFederatedClientScope(ctx context.Context, db *lion.Client, clientID, scope string) (*lion.OAuth2Clients, error) {
	client, err := db.OAuth2Clients.Query().Where(oauth2clients.ClientIDEQ(clientID),
		oauth2clients.ClientStatusEQ(int(adminv1.OAuth2Client_ACTIVE)), oauth2clients.DeletedAtIsNil()).Only(ctx)
	if err != nil && !lion.IsNotFound(err) {
		return nil, errs.Internal(ctx).WithMessage("failed to check OAuth2 client")
	}
	if err != nil || client.ClientID != clientID {
		return nil, errs.PermissionDenied(ctx).WithMessage("OAuth2 client is unavailable")
	}
	for value := range strings.FieldsSeq(scope) {
		if !slices.Contains(client.Scopes, value) {
			return nil, errs.PermissionDenied(ctx).WithMessage("invalid_scope: scope is not allowed for this client")
		}
	}
	if auth.HasFederatedScope(scope) && !slices.Contains(strings.Fields(scope), "openid") {
		return nil, errs.InvalidArgument(ctx).WithMessage("invalid_scope: federated scopes require openid")
	}
	return client, nil
}

func validateFederatedLoginAuthorization(ctx context.Context, db *lion.Client, request FederatedLoginAuthorization) error {
	if request.ExpiresAt.IsZero() {
		return errs.InvalidArgument(ctx).WithMessage("authorization deadline is required")
	}
	if !request.ExpiresAt.After(time.Now()) {
		return errs.Unauthenticated(ctx).WithMessage("authorization expired; please restart login")
	}
	if !auth.HasFederatedScope(request.Scope) {
		return errs.InvalidArgument(ctx).WithMessage("invalid federated login request")
	}
	client, err := validateFederatedClientScope(ctx, db, request.ClientID, request.Scope)
	if err != nil {
		return err
	}
	if !slices.Contains(client.GrantTypes, "authorization_code") || !slices.Contains(client.RedirectUris, request.RedirectURI) {
		return errs.PermissionDenied(ctx).WithMessage("authorization request is not allowed for this client")
	}
	return nil
}

func (a *KnownAdminAPI) loginIssuanceContext(ctx context.Context, approved *FederatedLoginAuthorization, ttl time.Duration) (AccessTokenIssuanceContext, error) {
	if approved == nil {
		return a.newAccessTokenIssuanceContext("", "", ttl)
	}
	db, err := a.federatedDB(ctx)
	if err != nil {
		return AccessTokenIssuanceContext{}, err
	}
	// 保存值副本，避免调用方或后续 HTTP 请求修改本次认证 / MFA
	// 已接受的授权参数。
	authorization := *approved
	if err := validateFederatedLoginAuthorization(ctx, db, authorization); err != nil {
		return AccessTokenIssuanceContext{}, err
	}
	authorization.Scope = canonicalScope(authorization.Scope)
	issuance, err := a.newAccessTokenIssuanceContext(authorization.ClientID, authorization.Scope, ttl)
	if err != nil {
		return issuance, err
	}
	issuance.authorization = &authorization
	return issuance, nil
}

func (a *KnownAdminAPI) applyFederatedLoginClaims(ctx context.Context, claims *auth.AccessTokenClaims, issuance AccessTokenIssuanceContext) error {
	if issuance.authorization == nil {
		return nil
	}
	db, err := a.federatedDB(ctx)
	if err != nil {
		return err
	}
	if err := validateFederatedLoginAuthorization(ctx, db, *issuance.authorization); err != nil {
		return err
	}
	if claims.ClientID != issuance.authorization.ClientID || canonicalScope(claims.Scope) != canonicalScope(issuance.authorization.Scope) {
		return errs.Unauthenticated(ctx).WithMessage("login token does not match its authorization")
	}
	if source := issuance.source; source != nil {
		if claims.Subject != strconv.Itoa(source.userID) {
			return errs.Unauthenticated(ctx).WithMessage("authentication source does not match the user")
		}
		claims.FederatedClaims = auth.ProjectFederatedClaims(claims.Scope, source.connectorID, source.subject, source.username)
	}
	return nil
}
