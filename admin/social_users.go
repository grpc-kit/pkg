package admin

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/lion/authusersocial"
	"github.com/grpc-kit/pkg/lion/securitykeys"
	"github.com/grpc-kit/pkg/lion/users"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"

	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
)

type socialUsers struct {
	logger *logrus.Entry
	db     *lion.Client

	aesKey     []byte
	privateKey *rsa.PrivateKey

	ProviderName string
	AuthProvider *lion.AuthProviders
}

func newSocialUsers(ctx context.Context, logger *logrus.Entry, aesKey []byte, db *lion.Client, providerName string) (*socialUsers, error) {
	ap, err := db.AuthProviders.Query().
		Select(
			authproviders.FieldName,
			authproviders.FieldType,
			authproviders.FieldEnabled,
			authproviders.FieldClientID,
			authproviders.FieldClientSecretEncrypted,
			authproviders.FieldIssuer,
			authproviders.FieldAuthorizationEndpoint,
			authproviders.FieldScopes,
			authproviders.FieldRedirectURI,
		).
		Where(
			authproviders.NameEQ(providerName),
		).Only(ctx)
	if err != nil {
		return nil, err
	}

	sk, err := db.SecurityKeys.Query().
		Select(securitykeys.FieldPrivateKeyEncrypted).
		Only(ctx)
	if err != nil {
		return nil, err
	}

	derBytes, err := crypto.DecryptAES(aesKey, sk.PrivateKeyEncrypted)
	if err != nil {
		return nil, err
	}

	// 解析为 PKCS#1 格式（这是您的格式）
	privateKey, err := x509.ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#1 private key: %v", err)
	}

	s := &socialUsers{
		logger:       logger,
		db:           db,
		aesKey:       aesKey,
		privateKey:   privateKey,
		ProviderName: providerName,
		AuthProvider: ap,
	}

	return s, nil
}

// Exchange 根据客户端上报的 code 进行二次验证返回 access_token
func (s *socialUsers) Exchange(ctx context.Context, code string) (string, error) {
	accessToken := ""

	idToken := &auth.IDTokenClaims{}

	switch s.AuthProvider.Type {
	case authproviders.TypeWECHAT:
		resp, err := s.weixinExchange(ctx, code)
		if err != nil {
			return "", err
		}

		userID, err := s.upsertUserWechat(ctx, resp)
		if err != nil {
			return "", err
		}

		// 填充 idToken 内容
		idToken.SetSubject(strconv.Itoa(userID))

		accessToken, err = idToken.GetAccessToken(resp.SessionKey)
		if err != nil {
			return accessToken, err
		}

		return accessToken, nil
	case authproviders.TypeOIDC:
		oauth2Token, err := s.oauth2Exchange(ctx, code)
		if err != nil {
			return accessToken, err
		}

		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			return accessToken, fmt.Errorf("get auth providers failed")
		}

		// 填充 idToken 内容
		_, err = jwt.ParseWithClaims(rawIDToken, idToken, func(token *jwt.Token) (interface{}, error) {
			return nil, nil
		})
		idToken.SetExpiresAt(oauth2Token.ExpiresIn)

		// 判断是否已存在数据库中
		userID, err := s.upsertUserOIDC(ctx, oauth2Token, idToken)
		if err != nil {
			return accessToken, err
		}

		// 填充 idToken 内容
		idToken.SetSubject(strconv.Itoa(userID))

		// 生成 jwt 返回客户端
		accessToken, err = idToken.GetAccessTokenRSA(s.privateKey)
		if err != nil {
			return accessToken, err
		}
	}

	return accessToken, nil
}

func (s *socialUsers) upsertUserOIDC(ctx context.Context, oauth2Token *oauth2.Token, idToken *auth.IDTokenClaims) (int, error) {
	existUserID, err := s.db.AuthUserSocial.Query().
		Where(
			authusersocial.ProviderNameEQ(s.ProviderName),
			authusersocial.ProviderUserIDEQ(idToken.Subject),
		).
		OnlyID(ctx)
	if err != nil && !lion.IsNotFound(err) {
		return 0, err
	}

	if existUserID == 0 && lion.IsNotFound(err) {
		// TODO; 新增用户，preferred username 如何定义，开启事务
		// 规范：provider_name_email_prefix
		username := strings.ToLower(fmt.Sprintf("%v_%v", s.ProviderName, idToken.Subject))

		// 首先确保 "lion_users" 不存在这个用户，开启一个事务
		tx, err := s.db.Tx(ctx)
		if err != nil {
			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		_, err = tx.Users.Query().Where(users.UsernameEQ(username)).OnlyID(ctx)
		if !lion.IsNotFound(err) {
			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		var emailEnc []byte
		emailEnc, err = crypto.EncryptAES(s.aesKey, []byte(idToken.Email))
		if err != nil {
			// TODO;
		}

		newUser, err := tx.Users.Create().
			SetUsername(username).
			SetEmailEncrypted(emailEnc).
			SetEmailVerified(idToken.EmailVerified).
			SetEmailHash(crypto.SHA256([]byte(idToken.Email))).
			Save(ctx)
		if err != nil {
			_ = tx.Rollback()

			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		var accessTokenEnc, refreshTokenEnc []byte
		if oauth2Token.AccessToken != "" {
			accessTokenEnc, err = crypto.EncryptAES(s.aesKey, []byte(oauth2Token.AccessToken))
		}
		if oauth2Token.RefreshToken != "" {
			refreshTokenEnc, err = crypto.EncryptAES(s.aesKey, []byte(oauth2Token.RefreshToken))
		}

		_, err = tx.AuthUserSocial.Create().
			SetUserID(newUser.ID).
			SetProviderName(s.ProviderName).
			SetProviderUserID(idToken.Subject).
			SetAccessTokenEncrypted(accessTokenEnc).
			SetRefreshTokenEncrypted(refreshTokenEnc).
			SetTokenExpiresAt(oauth2Token.Expiry).
			Save(ctx)
		if err != nil {
			_ = tx.Rollback()

			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		existUserID = newUser.ID

		_ = tx.Commit()
	} else {
		var accessTokenEnc, refreshTokenEnc []byte
		if oauth2Token.AccessToken != "" {
			accessTokenEnc, err = crypto.EncryptAES(s.aesKey, []byte(oauth2Token.AccessToken))
		}
		if oauth2Token.RefreshToken != "" {
			refreshTokenEnc, err = crypto.EncryptAES(s.aesKey, []byte(oauth2Token.RefreshToken))
		}

		s.db.AuthUserSocial.Update().
			Where(authusersocial.IDEQ(existUserID)).
			SetAccessTokenEncrypted(accessTokenEnc).
			SetRefreshTokenEncrypted(refreshTokenEnc).
			SetTokenExpiresAt(oauth2Token.Expiry)
	}

	return existUserID, nil
}

func (s *socialUsers) oauth2Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	op, err := oidc.NewProvider(ctx, s.AuthProvider.Issuer)
	if err != nil {
		return nil, err
	}

	var clientSecret []byte
	clientSecret, err = crypto.DecryptAES(s.aesKey, s.AuthProvider.ClientSecretEncrypted)
	if err != nil {
		return nil, err
	}

	oauth2Config := oauth2.Config{
		ClientID:     s.AuthProvider.ClientID,
		ClientSecret: string(clientSecret),
		Endpoint:     op.Endpoint(),
		Scopes:       strings.Split(s.AuthProvider.Scopes, " "),
		RedirectURL:  s.AuthProvider.RedirectURI,
	}

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (s *socialUsers) weixinExchange(ctx context.Context, code string) (*wechatCode2SessionResponse, error) {
	var clientSecret []byte
	clientSecret, err := crypto.DecryptAES(s.aesKey, s.AuthProvider.ClientSecretEncrypted)
	if err != nil {
		return nil, err
	}

	wx := newWechatOpen(s.logger, s.AuthProvider.ClientID, string(clientSecret))
	return wx.code2Session(s.AuthProvider.AuthorizationEndpoint, code)
}

func (s *socialUsers) upsertUserWechat(ctx context.Context, resp *wechatCode2SessionResponse) (int, error) {
	existUserID, err := s.db.AuthUserSocial.Query().
		Where(
			authusersocial.ProviderNameEQ(s.ProviderName),
			authusersocial.ProviderUserIDEQ(resp.Openid),
		).
		OnlyID(ctx)
	if err != nil && !lion.IsNotFound(err) {
		return existUserID, err
	}

	if existUserID == 0 && lion.IsNotFound(err) {
		// TODO; 新增用户，preferred username 如何定义，开启事务
		// 规范：provider_name_email_prefix
		username := strings.ToLower(fmt.Sprintf("%v_%v", s.ProviderName, resp.Openid))

		// 首先确保 "lion_users" 不存在这个用户，开启一个事务
		tx, err := s.db.Tx(ctx)
		if err != nil {
			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		_, err = tx.Users.Query().Where(users.UsernameEQ(username)).OnlyID(ctx)
		if !lion.IsNotFound(err) {
			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		/*
			var emailEnc []byte
			emailEnc, err = crypto.EncryptAES(s.aesKey, []byte(idToken.Email))
			if err != nil {
				// TODO;
			}
		*/

		newUser, err := tx.Users.Create().
			SetUsername(username).
			//SetEmailEncrypted(emailEnc).
			//SetEmailVerified(idToken.EmailVerified).
			//SetEmailHash(crypto.SHA256([]byte(idToken.Email))).
			Save(ctx)
		if err != nil {
			_ = tx.Rollback()

			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		var accessTokenEnc, refreshTokenEnc []byte
		if resp.SessionKey != "" {
			accessTokenEnc, err = crypto.EncryptAES(s.aesKey, []byte(resp.SessionKey))
			refreshTokenEnc = accessTokenEnc
		}

		_, err = tx.AuthUserSocial.Create().
			SetUserID(newUser.ID).
			SetProviderName(s.ProviderName).
			SetProviderUserID(resp.Openid).
			SetAccessTokenEncrypted(accessTokenEnc).
			SetRefreshTokenEncrypted(refreshTokenEnc).
			//SetTokenExpiresAt(oauth2Token.Expiry).
			Save(ctx)
		if err != nil {
			_ = tx.Rollback()

			s.logger.Errorf("create user: %v, err: %v", username, err)
			return 0, fmt.Errorf("create user failed")
		}

		existUserID = newUser.ID

		_ = tx.Commit()
	}

	return existUserID, nil
}
