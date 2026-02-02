package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
	"google.golang.org/protobuf/types/known/emptypb"
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
			Code:    "local",
			Type:    adminv1.AuthProvider_LOCAL,
			Enabled: true,
		})

		return result, nil
	}

	selectFields := []string{
		authproviders.FieldID,
		authproviders.FieldCode,
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
			Id:                    int64(row.ID),
			Code:                  row.Code,
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
		name := p.Code
		existID, err := db.AuthProviders.Query().Where(authproviders.CodeEQ(name)).OnlyID(ctx)
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
				SetCode(name).
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
			x := db.AuthProviders.Update().Where(authproviders.CodeEQ(name))

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

	if req.Provider == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body provider is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// TODO; 权限验证
	x, err := db.AuthProviders.Create().
		SetCode(req.Provider.Code).
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

	result.Id = int64(x.ID)
	result.Code = x.Code
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

// GetAuthProvider 获取认证提供方
func (a *KnownAdminAPI) GetAuthProvider(ctx context.Context, req *adminv1.GetAuthProviderRequest) (*adminv1.AuthProvider, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("provider id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 查询认证提供方
	provider, err := db.AuthProviders.Get(ctx, int(req.Id))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("auth provider not found")
		}
		return nil, err
	}

	// 解密 ClientSecret
	var clientSecret string
	if len(provider.ClientSecretEncrypted) > 0 {
		decrypted, err := crypto.DecryptAES(a.config.aesKey, provider.ClientSecretEncrypted)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage("failed to decrypt client secret")
		}
		clientSecret = string(decrypted)
	}

	result := &adminv1.AuthProvider{
		Id:                    int64(provider.ID),
		Code:                  provider.Code,
		Type:                  adminv1.AuthProvider_Type(provider.ProviderType),
		ClientId:              provider.ClientID,
		ClientSecret:          clientSecret,
		Enabled:               provider.Enabled,
		RedirectUri:           provider.RedirectURI,
		Scopes:                provider.Scopes,
		Issuer:                provider.Issuer,
		AuthorizationEndpoint: provider.AuthorizationEndpoint,
		TokenEndpoint:         provider.TokenEndpoint,
		UserinfoEndpoint:      provider.UserinfoEndpoint,
	}

	return result, nil
}

// DeleteAuthProvider 删除认证提供方
func (a *KnownAdminAPI) DeleteAuthProvider(ctx context.Context, req *adminv1.DeleteAuthProviderRequest) (*emptypb.Empty, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("provider id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 检查认证提供方是否存在
	_, err = db.AuthProviders.Get(ctx, int(req.Id))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("auth provider not found")
		}
		return nil, err
	}

	// 执行删除
	err = db.AuthProviders.DeleteOneID(int(req.Id)).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// UpdateAuthProvider 更新认证提供方
func (a *KnownAdminAPI) UpdateAuthProvider(ctx context.Context, req *adminv1.UpdateAuthProviderRequest) (*adminv1.AuthProvider, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("provider id is required")
	}

	if req.Provider == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body provider is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 查找要更新的认证提供方
	provider, err := db.AuthProviders.Get(ctx, int(req.Id))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("auth provider not found")
		}
		return nil, err
	}

	// 构建更新操作
	update := provider.Update()

	// 根据请求设置更新字段
	if req.Provider.Code != "" {
		update.SetCode(req.Provider.Code)
	}
	if req.Provider.Type != adminv1.AuthProvider_TYPE_UNSPECIFIED {
		update.SetProviderType(int(req.Provider.Type.Number()))
	}
	if req.Provider.ClientId != "" {
		update.SetClientID(req.Provider.ClientId)
	}
	// 如果提供了 ClientSecret，则加密并更新
	if req.Provider.ClientSecret != "" {
		clientSecretEnc, err := crypto.EncryptAES(a.config.aesKey, []byte(req.Provider.ClientSecret))
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage("failed to encrypt client secret")
		}
		update.SetClientSecretEncrypted(clientSecretEnc)
	}
	update.SetEnabled(req.Provider.Enabled)
	if req.Provider.RedirectUri != "" {
		update.SetRedirectURI(req.Provider.RedirectUri)
	}
	if req.Provider.Scopes != "" {
		update.SetScopes(req.Provider.Scopes)
	}
	if req.Provider.Issuer != "" {
		update.SetIssuer(req.Provider.Issuer)
	}
	if req.Provider.AuthorizationEndpoint != "" {
		update.SetAuthorizationEndpoint(req.Provider.AuthorizationEndpoint)
	}
	if req.Provider.TokenEndpoint != "" {
		update.SetTokenEndpoint(req.Provider.TokenEndpoint)
	}
	if req.Provider.UserinfoEndpoint != "" {
		update.SetUserinfoEndpoint(req.Provider.UserinfoEndpoint)
	}

	// 执行更新
	updatedProvider, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}

	// 解密 ClientSecret 用于返回
	var clientSecret string
	if len(updatedProvider.ClientSecretEncrypted) > 0 {
		decrypted, err := crypto.DecryptAES(a.config.aesKey, updatedProvider.ClientSecretEncrypted)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage("failed to decrypt client secret")
		}
		clientSecret = string(decrypted)
	}

	result := &adminv1.AuthProvider{
		Id:                    int64(updatedProvider.ID),
		Code:                  updatedProvider.Code,
		Type:                  adminv1.AuthProvider_Type(updatedProvider.ProviderType),
		ClientId:              updatedProvider.ClientID,
		ClientSecret:          clientSecret,
		Enabled:               updatedProvider.Enabled,
		RedirectUri:           updatedProvider.RedirectURI,
		Scopes:                updatedProvider.Scopes,
		Issuer:                updatedProvider.Issuer,
		AuthorizationEndpoint: updatedProvider.AuthorizationEndpoint,
		TokenEndpoint:         updatedProvider.TokenEndpoint,
		UserinfoEndpoint:      updatedProvider.UserinfoEndpoint,
	}

	return result, nil
}
