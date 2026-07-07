package admin

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"reflect"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion/credentials"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// CreateCredential 生成签名密钥
func (a *KnownAdminAPI) CreateCredential(ctx context.Context, req *adminv1.CreateCredentialRequest) (*adminv1.Credential, error) {
	result := &adminv1.Credential{}

	// 仅允许存在一条记录，如已存在多次创建返回已存在内容

	/*
		tx, err := a.config.db.Tx(ctx)
		if err != nil {
			return nil, err
		}

		key, err := tx.Credentials.Query().Select(credentials.FieldPublicKey).Only(ctx)
		if err != nil && !lion.IsNotFound(err) {
			return nil, err
		}

		// 不存在记录则新建
		if lion.IsNotFound(err) {
			privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, err
			}

			privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
			publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
			if err != nil {
				return nil, err
			}

			privateKeyEnc, err := crypto.EncryptAES(a.config.aesKey, privateKeyBytes)
			if err != nil {
				return nil, err
			}

			appid := uuid.New().String()
			if req.Credential.Appid != "" {
				appid = req.Credential.Appid
			}

			tx.Credentials.Create().
				SetName(req.Credential.Name).
				SetType(int(req.Credential.Type)).
				SetAppid(appid).
				SetUsage(req.Credential.Usage).
				SetPublicKey(crypto.Base64Encode(publicKeyBytes)).
				SetPrivateKeyEncrypted(privateKeyEnc).SaveX(ctx)

			result.PublicKey = crypto.Base64Encode(publicKeyBytes)
		} else {
			result.PublicKey = key.PublicKey
		}

		_ = tx.Commit()
	*/

	return result, nil
}

// GetOAuth2Discovery 获取内置 OpenID 配置
func (a *KnownAdminAPI) GetOAuth2Discovery(ctx context.Context, req *emptypb.Empty) (*adminv1.OAuth2Discovery, error) {
	result := &adminv1.OAuth2Discovery{}

	issuer := "http://127.0.0.1:8080/builtin/admin/api/v1/oauth2"

	if a.config.issuer != "" {
		issuer = a.config.issuer
	}

	result.Issuer = issuer
	result.AuthorizationEndpoint = issuer + "/authorize"
	result.TokenEndpoint = issuer + "/token"
	result.JwksUri = issuer + "/jwks"

	result.ResponseTypesSupported = []string{"none"}
	result.SubjectTypesSupported = []string{"public"}
	result.IdTokenSigningAlgValuesSupported = []string{"RS256"}

	return result, nil
}

// GetOAuth2JSONWebKeys 获取内置 OpenID 公钥
func (a *KnownAdminAPI) GetOAuth2JSONWebKeys(ctx context.Context, req *emptypb.Empty) (*adminv1.OAuth2JSONWebKeys, error) {
	result := &adminv1.OAuth2JSONWebKeys{
		Keys: make([]*adminv1.OAuth2JSONWebKeys_Key, 0),
	}

	sk, err := a.config.db.Credentials.Query().
		Select(
			credentials.FieldKeyID,
			credentials.FieldPublicKey,
		).
		Where(
			credentials.CredentialTypeEQ(int(adminv1.Credential_JWKS.Number())),
			credentials.CredentialAlgorithmEQ(int(adminv1.Credential_RSA.Number())),
			credentials.CredentialUsageEQ(int(adminv1.Credential_SIGNING.Number())),
			credentials.CredentialVisibilityEQ(int(adminv1.Visibility_VISIBILITY_RESTRICTED.Number())),
			credentials.CredentialStatusEQ(int(adminv1.Credential_ACTIVE.Number())),
			credentials.CredentialSourceEQ(int(adminv1.Credential_SYSTEM.Number())),
		).
		Order(credentials.ByID()).
		Only(ctx)
	if err != nil {
		return nil, err
	}

	derBytes := crypto.Base64Decode(sk.PublicKey)
	pubInterface, err := x509.ParsePKIXPublicKey(derBytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	// 将模数 N 和指数 E 转换为 Base64URL 编码
	n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

	tmp := &adminv1.OAuth2JSONWebKeys_Key{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		E:   e,
		N:   n,
		Kid: sk.KeyID,
	}

	result.Keys = append(result.Keys, tmp)

	return result, nil
}

// GetOAuth2Userinfo 获取内置 OpenID 用户信息
func (a *KnownAdminAPI) GetOAuth2Userinfo(ctx context.Context, req *emptypb.Empty) (*adminv1.OAuth2Userinfo, error) {
	result := &adminv1.OAuth2Userinfo{}

	tmp := rpc.GetIDTokenFromContext(ctx)
	a.logger.Infof("get id token type: %v", reflect.TypeOf(tmp))
	idToken, ok := tmp.(auth.IDTokenClaims)
	if !ok {
		return result, errs.PermissionDenied(ctx)
	}

	result.UserId = idToken.GetMustUserID()
	result.Username = idToken.Username
	result.Nickname = idToken.Nickname

	return result, nil
}
