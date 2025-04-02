package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion/authproviders"
)

func (a *KnownAdminAPI) GetConfig(ctx context.Context, req *adminv1.GetConfigRequest) (*adminv1.GetConfigResponse, error) {
	result := &adminv1.GetConfigResponse{}
	return result, nil
}

func (a *KnownAdminAPI) CreateAuthLogin(ctx context.Context, req *adminv1.CreateAuthLoginRequest) (*adminv1.CreateAuthLoginResponse, error) {
	result := &adminv1.CreateAuthLoginResponse{Token: "test"}
	return result, nil
}

func (a *KnownAdminAPI) GetAuthProviders(ctx context.Context, req *adminv1.GetAuthProvidersRequest) (*adminv1.GetAuthProvidersResponse, error) {
	result := &adminv1.GetAuthProvidersResponse{
		Providers: make([]*adminv1.AuthProvider, 0),
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("get lion client failed")
	}

	rows := db.AuthProviders.Query().AllX(ctx)
	for _, row := range rows {
		p := &adminv1.AuthProvider{
			ClientId:     row.ClientID,
			ClientSecret: row.ClientSecretEncrypted,
			Enabled:      row.Enabled,
			AuthUrl:      row.AuthURL,
			TokenUrl:     row.TokenURL,
			UserInfoUrl:  row.UserInfoURL,
			Scopes:       row.Scopes,
			RedirectUrl:  row.RedirectURL,
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

func (a *KnownAdminAPI) UpsertAuthProviders(ctx context.Context, req *adminv1.UpsertAuthProvidersRequest) (*adminv1.UpsertAuthProvidersResponse, error) {
	result := &adminv1.UpsertAuthProvidersResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("get lion client failed")
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

		_, err := db.AuthProviders.Create().
			SetName(name).
			SetClientID(p.ClientId).
			SetClientSecretEncrypted(p.ClientSecret).
			SetAuthURL(p.AuthUrl).
			SetTokenURL(p.TokenUrl).
			SetUserInfoURL(p.UserInfoUrl).
			SetScopes(p.Scopes).
			SetRedirectURL(p.RedirectUrl).
			Save(ctx)

		if err != nil {
			return nil, err
		}
	}

	return result, nil
}
