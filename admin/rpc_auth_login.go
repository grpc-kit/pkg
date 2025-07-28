package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
)

// GetConfig 获取配置内容
func (a *KnownAdminAPI) GetConfig(ctx context.Context, req *adminv1.GetConfigRequest) (*adminv1.GetConfigResponse, error) {
	result := &adminv1.GetConfigResponse{}
	return result, nil
}

// CreateAuthLogin 创建登录认证
func (a *KnownAdminAPI) CreateAuthLogin(ctx context.Context, req *adminv1.CreateAuthLoginRequest) (*adminv1.CreateAuthLoginResponse, error) {
	result := &adminv1.CreateAuthLoginResponse{TokenType: "Bearer"}

	// TODO; 当前先支持静态用户登录
	if a.config.staticUsers == nil {
		return nil, errs.Unauthenticated(ctx)
	}

	if req.Username == "" {
		return nil, errs.Unauthenticated(ctx)
	}

	u, ok := a.config.staticUsers.Valid(req.Username, req.PasswordHash)
	if !ok {
		return nil, errs.Unauthenticated(ctx)
	}

	expiresIn := req.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 24 * 60 * 60
	}

	tk, err := u.GetAccessToken(expiresIn)
	if err != nil {
		return nil, errs.Unauthenticated(ctx).WithMessage(err.Error())
	}

	result.AccessToken = tk
	result.ExpiresIn = expiresIn

	return result, nil
}

// ListAuthProviders 获取认证提供列表
func (a *KnownAdminAPI) ListAuthProviders(ctx context.Context, req *adminv1.ListAuthProvidersRequest) (*adminv1.ListAuthProvidersResponse, error) {
	result := &adminv1.ListAuthProvidersResponse{
		Providers: make([]*adminv1.AuthProvider, 0),
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	selectFields := []string{
		"name",
		"client_id",
		"enabled",
		"scopes",
		"redirect_uri",
		"issuer",
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
	}

	rows := db.AuthProviders.Query().Select(selectFields...).AllX(ctx)
	for _, row := range rows {
		p := &adminv1.AuthProvider{
			ClientId:              row.ClientID,
			Enabled:               row.Enabled,
			Issuer:                row.Issuer,
			AuthorizationEndpoint: row.AuthorizationEndpoint,
			TokenEndpoint:         row.TokenEndpoint,
			UserinfoEndpoint:      row.UserinfoEndpoint,
			Scopes:                row.Scopes,
			RedirectUri:           row.RedirectURI,
		}

		switch row.Name {
		case authproviders.NameLOCAL:
			p.Name = adminv1.AuthProvider_LOCAL
		case authproviders.NameLDAP:
			p.Name = adminv1.AuthProvider_LDAP
		case authproviders.NameOIDC:
			p.Name = adminv1.AuthProvider_OIDC
		case authproviders.NameOAUTH2:
			p.Name = adminv1.AuthProvider_OAUTH2
		case authproviders.NameGITHUB:
			p.Name = adminv1.AuthProvider_GITHUB
		case authproviders.NameWECHAT:
			p.Name = adminv1.AuthProvider_WECHAT
		case authproviders.NameGOOGLE:
			p.Name = adminv1.AuthProvider_GOOGLE
		}

		result.Providers = append(result.Providers, p)
	}

	return result, nil
}

// UpsertAuthProviders 更新认证提供方列表
func (a *KnownAdminAPI) UpsertAuthProviders(ctx context.Context, req *adminv1.UpsertAuthProvidersRequest) (*adminv1.UpsertAuthProvidersResponse, error) {
	result := &adminv1.UpsertAuthProvidersResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	for _, p := range req.Providers {
		name := authproviders.NameLDAP
		switch p.GetName() {
		case adminv1.AuthProvider_LOCAL:
			name = authproviders.NameLOCAL
		case adminv1.AuthProvider_LDAP:
			name = authproviders.NameLDAP
		case adminv1.AuthProvider_OIDC:
			name = authproviders.NameOIDC
		case adminv1.AuthProvider_OAUTH2:
			name = authproviders.NameOAUTH2
		case adminv1.AuthProvider_GITHUB:
			name = authproviders.NameGITHUB
		case adminv1.AuthProvider_WECHAT:
			name = authproviders.NameWECHAT
		case adminv1.AuthProvider_GOOGLE:
			name = authproviders.NameGOOGLE
		default:
			a.logger.Warnf("auth provider name not found %v", p.Name.String())
			continue
		}

		existID, err := db.AuthProviders.Query().Where(authproviders.NameEQ(name)).OnlyID(ctx)
		if err != nil && !lion.IsNotFound(err) {
			return nil, err
		}

		var clientSecretEnc []byte
		clientSecretEnc, err = crypto.EncryptAES(a.config.aesKey, []byte(p.ClientSecret))
		if err != nil {
			// return nil, err
		}

		if existID == 0 {
			_, err = db.AuthProviders.Create().
				SetName(name).
				SetEnabled(p.Enabled).
				SetClientID(p.ClientId).
				SetClientSecretEncrypted(clientSecretEnc).
				SetIssuer(p.Issuer).
				SetAuthorizationEndpoint(p.AuthorizationEndpoint).
				SetTokenEndpoint(p.TokenEndpoint).
				SetUserinfoEndpoint(p.UserinfoEndpoint).
				SetScopes(p.Scopes).
				SetRedirectURI(p.RedirectUri).
				Save(ctx)
		} else {
			x := db.AuthProviders.Update().Where(authproviders.NameEQ(name))

			if p.ClientId != "" {
				x.SetClientID(p.ClientId)
			}
			if len(clientSecretEnc) > 0 {
				x.SetClientSecretEncrypted(clientSecretEnc)
			}
			if p.Issuer != "" {
				x.SetIssuer(p.Issuer)
			}
			if p.AuthorizationEndpoint != "" {
				x.SetAuthorizationEndpoint(p.AuthorizationEndpoint)
			}
			if p.TokenEndpoint != "" {
				x.SetTokenEndpoint(p.TokenEndpoint)
			}
			if p.UserinfoEndpoint != "" {
				x.SetUserinfoEndpoint(p.UserinfoEndpoint)
			}
			if p.Scopes != "" {
				x.SetScopes(p.Scopes)
			}
			if p.RedirectUri != "" {
				x.SetRedirectURI(p.RedirectUri)
			}
			err = x.Exec(ctx)
		}

		if err != nil {
			return nil, err
		}
	}

	return result, nil
}
