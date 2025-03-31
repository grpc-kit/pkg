package admin

import (
	"context"
	"strings"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion/authproviders"
)

func (a *KnownAdminAPI) GetConfig(ctx context.Context, req *adminv1.GetConfigRequest) (*adminv1.GetConfigResponse, error) {
	result := &adminv1.GetConfigResponse{}
	return result, nil
}

func (a *KnownAdminAPI) CreateAuthLogin(ctx context.Context, req *adminv1.CreateAuthLoginRequest) (*adminv1.CreateAuthLoginResponse, error) {
	result := &adminv1.CreateAuthLoginResponse{}
	return result, nil
}

func (a *KnownAdminAPI) GetAuthProviders(ctx context.Context, req *adminv1.GetAuthProvidersRequest) (*adminv1.GetAuthProvidersResponse, error) {
	result := &adminv1.GetAuthProvidersResponse{}
	return result, nil
}

func (a *KnownAdminAPI) UpsertAuthProviders(ctx context.Context, req *adminv1.UpsertAuthProvidersRequest) (*adminv1.UpsertAuthProvidersResponse, error) {
	result := &adminv1.UpsertAuthProvidersResponse{}

	db := a.GetLionClient()

	for _, p := range req.AuthProviders {
		name := authproviders.NameLDAP
		switch p.GetName() {
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
			SetScopes(strings.Fields(p.Scopes)).
			SetRedirectURL(p.RedirectUrl).
			Save(ctx)

		if err != nil {
			return nil, err
		}
	}

	return result, nil
}
