package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
)

// CreateAuthLogin 创建登录认证
func (a *KnownAdminAPI) CreateAuthLogin(ctx context.Context, req *adminv1.CreateAuthLoginRequest) (*adminv1.AuthToken, error) {
	result := &adminv1.AuthToken{TokenType: "Bearer"}

	var accessToken string

	if req.Username == "" {
		return nil, errs.Unauthenticated(ctx)
	}

	// TODO; 不允许创建过长过期的 token
	expiresIn := req.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 24 * 60 * 60
	}

	hasDBEnabled := false
	db, err := a.GetLionClient()
	if err == nil && db != nil {
		hasDBEnabled = true
	}

	if a.config.staticUsers == nil && hasDBEnabled == false {
		return nil, errs.Unauthenticated(ctx)
	}

	// 优先本地静态用户验证
	u, ok := a.config.staticUsers.Valid(req.Username, req.PasswordHash)
	if ok {
		tk, err := u.GetAccessToken(expiresIn, "")
		if err != nil {
			return nil, errs.Unauthenticated(ctx).WithMessage(err.Error())
		}

		accessToken = tk
	} else {
		// 尝试数据库验证
		// 根据不同的 provider_name 选择个性处理方式
		su, err := newSocialUsers(ctx, a.logger, a.config.aesKey, db, "local")
		if err != nil {
			return nil, err
		}

		tk, ok, err := su.PasswordCheck(ctx, req.Username, req.PasswordHash)
		if err != nil {
			return nil, errs.Unauthenticated(ctx).WithMessage(err.Error())
		}
		if !ok {
			return nil, errs.Unauthenticated(ctx)
		}

		accessToken = tk
	}

	result.AccessToken = accessToken
	result.ExpiresIn = expiresIn

	return result, nil
}

// CreateAuthToken 创建认证令牌
func (a *KnownAdminAPI) CreateAuthToken(ctx context.Context, req *adminv1.CreateAuthTokenRequest) (*adminv1.AuthToken, error) {
	result := &adminv1.AuthToken{TokenType: "Bearer"}

	appid := req.Appid
	if appid == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("create token must with appid")
	}

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

	tk, err := u.GetAccessToken(expiresIn, appid)
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
		if a.config.staticUsers == nil || a.config.staticUsers.Len() == 0 {
			return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
		}

		// 支持本地登录
		result.Providers = append(result.Providers, &adminv1.AuthProvider{
			Name:    "local",
			Type:    adminv1.AuthProvider_TYPE_LOCAL,
			Enabled: true,
		})

		return result, nil
	}

	selectFields := []string{
		authproviders.FieldID,
		authproviders.FieldName,
		authproviders.FieldProviderType,
		authproviders.FieldClientID,
		authproviders.FieldEnabled,
		authproviders.FieldScopes,
		authproviders.FieldRedirectURI,
		authproviders.FieldIssuer,
		authproviders.FieldAuthorizationEndpoint,
		authproviders.FieldTokenEndpoint,
		authproviders.FieldUserinfoEndpoint,
	}

	rows := db.AuthProviders.Query().Select(selectFields...).AllX(ctx)
	for _, row := range rows {
		p := &adminv1.AuthProvider{
			Id:                    int32(row.ID),
			Name:                  row.Name,
			ClientId:              row.ClientID,
			Enabled:               row.Enabled,
			Issuer:                row.Issuer,
			AuthorizationEndpoint: row.AuthorizationEndpoint,
			TokenEndpoint:         row.TokenEndpoint,
			UserinfoEndpoint:      row.UserinfoEndpoint,
			Scopes:                row.Scopes,
			RedirectUri:           row.RedirectURI,
			Type:                  adminv1.AuthProvider_Type(row.ProviderType),
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
		name := p.Name
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
				SetProviderType(int(p.GetType())).
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

// CreateAuthProvider 创建认证提供方
func (a *KnownAdminAPI) CreateAuthProvider(ctx context.Context, req *adminv1.CreateAuthProviderRequest) (*adminv1.AuthProvider, error) {
	result := &adminv1.AuthProvider{}

	// TODO; 权限验证
	x, err := a.config.db.AuthProviders.Create().
		SetName(req.Provider.Name).
		SetProviderType(int(req.Provider.Type.Number())).
		SetEnabled(req.Provider.Enabled).
		SetClientID(req.Provider.ClientId).
		SetClientSecretEncrypted(crypto.EncryptAESMust(a.config.aesKey, []byte(req.Provider.ClientSecret))).
		SetIssuer(req.Provider.Issuer).
		SetAuthorizationEndpoint(req.Provider.AuthorizationEndpoint).
		SetTokenEndpoint(req.Provider.TokenEndpoint).
		SetUserinfoEndpoint(req.Provider.UserinfoEndpoint).
		SetScopes(req.Provider.Scopes).
		SetRedirectURI(req.Provider.RedirectUri).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	result.Id = int32(x.ID)
	result.Name = x.Name
	result.Type = adminv1.AuthProvider_Type(x.ProviderType)
	result.ClientId = x.ClientID
	result.Enabled = x.Enabled
	result.RedirectUri = x.RedirectURI
	result.Scopes = x.Scopes
	result.AuthorizationEndpoint = x.AuthorizationEndpoint
	result.TokenEndpoint = x.TokenEndpoint
	result.UserinfoEndpoint = x.UserinfoEndpoint

	return result, nil
}
