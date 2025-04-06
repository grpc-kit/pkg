package admin

import (
	"context"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
	"github.com/grpc-kit/pkg/lion/userauthsocial"
	"github.com/grpc-kit/pkg/lion/users"
	"golang.org/x/oauth2"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
)

func (a *KnownAdminAPI) GetAuthCallback(ctx context.Context, req *adminv1.GetAuthCallbackRequest) (*adminv1.GetAuthCallbackResponse, error) {
	result := &adminv1.GetAuthCallbackResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 根据不同的 provider_name 选择个性处理方式

	ap, err := db.AuthProviders.Query().
		Select(
			"name",
			"enabled",
			"client_id",
			"client_secret_encrypted",
			"issuer",
			"scopes",
			"redirect_url",
		).
		Where(
			authproviders.NameEQ(authproviders.Name(strings.ToUpper(req.ProviderName))),
		).Only(ctx)
	if err != nil {
		a.logger.Errorf("get auth providers failed: %v", err)

		return nil, errs.Internal(ctx).WithMessage("get auth providers failed")
	}

	op, err := oidc.NewProvider(ctx, ap.Issuer)
	if err != nil {
		a.logger.Errorf("get auth providers failed: %v", err)

		return nil, errs.Internal(ctx).WithMessage(err.Error())
	}

	var clientSecret []byte
	clientSecret, err = crypto.DecryptAES(a.config.aesKey, []byte(ap.ClientSecretEncrypted))
	if err != nil {
		// TODO;
	}

	oauth2Config := oauth2.Config{
		ClientID:     ap.ClientID,
		ClientSecret: string(clientSecret),
		Endpoint:     op.Endpoint(),
		Scopes:       strings.Split(ap.Scopes, " "),
		RedirectURL:  ap.RedirectURL,
	}

	oauth2Token, err := oauth2Config.Exchange(ctx, req.Code)
	if err != nil {
		a.logger.Errorf("get auth providers failed: %v", err)

		return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		a.logger.Errorf("get auth providers failed: %v", err)

		return nil, errs.InvalidArgument(ctx).WithMessage("get auth providers failed")
	}

	result.AccessToken = oauth2Token.AccessToken
	result.TokenType = oauth2Token.TokenType

	// TODO: parse token
	// 解析 id_token 并加入用户
	var idToken auth.IDTokenClaims
	_, err = jwt.ParseWithClaims(rawIDToken, &idToken, func(token *jwt.Token) (interface{}, error) {
		return nil, nil
	})

	existUserID, err := db.UserAuthSocial.Query().
		Where(
			userauthsocial.ProviderNameEQ(strings.ToUpper(req.ProviderName)),
			userauthsocial.ProviderUserIDEQ(idToken.Subject),
		).
		OnlyID(ctx)

	if err != nil && !lion.IsNotFound(err) {
		a.logger.Errorf("found user auth social failed: %v", err)

		return nil, errs.Internal(ctx).WithMessage("get user auth social failed")
	}

	if existUserID == 0 && lion.IsNotFound(err) {
		// TODO; 新增用户，preferred username 如何定义，开启事务
		// 规范：provider_name_email_prefix
		username := strings.ToLower(fmt.Sprintf("%v_%v", req.ProviderName, idToken.Subject))

		// 首先确保 "lion_users" 不存在这个用户，开启一个事务
		tx, err := db.Tx(ctx)
		if err != nil {
			a.logger.Errorf("create user failed: %v", err)
			return nil, errs.Internal(ctx).WithMessage("create user failed")
		}

		_, err = tx.Users.Query().Where(users.PreferredUsernameEQ(username)).OnlyID(ctx)
		if !lion.IsNotFound(err) {
			a.logger.Errorf("create user failed: %v", err)
			return nil, errs.Internal(ctx).WithMessage("create user failed")
		}

		var emailEnc []byte
		emailEnc, err = crypto.EncryptAES(a.config.aesKey, []byte(idToken.Email))
		if err != nil {
			// TODO;
		}

		newUser, err := tx.Users.Create().
			SetPreferredUsername(username).
			SetEmailEncrypted(emailEnc).
			SetEmailVerified(idToken.EmailVerified).
			Save(ctx)
		if err != nil {
			_ = tx.Rollback()

			a.logger.Errorf("create user failed: %v", err)
			return nil, errs.Internal(ctx).WithMessage("create user failed")
		}

		var accessTokenEnc, refreshTokenEnc []byte
		if oauth2Token.AccessToken != "" {
			accessTokenEnc, err = crypto.EncryptAES(a.config.aesKey, []byte(oauth2Token.AccessToken))
		}
		if oauth2Token.RefreshToken != "" {
			refreshTokenEnc, err = crypto.EncryptAES(a.config.aesKey, []byte(oauth2Token.RefreshToken))
		}

		_, err = tx.UserAuthSocial.Create().
			SetUserID(newUser.ID).
			SetProviderName(strings.ToUpper(req.ProviderName)).
			SetProviderUserID(idToken.Subject).
			SetAccessTokenEncrypted(accessTokenEnc).
			SetRefreshTokenEncrypted(refreshTokenEnc).
			SetTokenExpiresAt(oauth2Token.Expiry).
			Save(ctx)
		if err != nil {
			_ = tx.Rollback()

			a.logger.Errorf("create user failed: %v", err)
			return nil, errs.Internal(ctx).WithMessage("create user failed")
		}

		_ = tx.Commit()
	} else {
		db.UserAuthSocial.Update().
			Where(userauthsocial.IDEQ(existUserID)).
			SetAccessTokenEncrypted([]byte(oauth2Token.AccessToken)).
			SetRefreshTokenEncrypted([]byte(oauth2Token.RefreshToken)).
			SetTokenExpiresAt(oauth2Token.Expiry)
	}

	return result, nil
}
