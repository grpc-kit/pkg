package admin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/securitykeys"
	"google.golang.org/protobuf/types/known/emptypb"
)

// CreateSecurityKey 生成签名密钥
func (a *KnownAdminAPI) CreateSecurityKey(ctx context.Context, req *adminv1.CreateSecurityKeyRequest) (*adminv1.SecurityKey, error) {
	result := &adminv1.SecurityKey{}

	// 仅允许存在一条记录，如已存在多次创建返回已存在内容

	tx, err := a.config.db.Tx(ctx)
	if err != nil {
		return nil, err
	}

	key, err := tx.SecurityKeys.Query().Select(securitykeys.FieldPublicKey).Only(ctx)
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

		tx.SecurityKeys.Create().
			SetPublicKey(crypto.Base64Encode(publicKeyBytes)).
			SetPrivateKeyEncrypted(privateKeyEnc).SaveX(ctx)

		result.PublicKey = crypto.Base64Encode(publicKeyBytes)
	} else {
		result.PublicKey = key.PublicKey
	}

	_ = tx.Commit()

	return result, nil
}

// GetOAuth2Discovery 获取内置 OpenID 配置
func (a *KnownAdminAPI) GetOAuth2Discovery(ctx context.Context, req *emptypb.Empty) (*adminv1.OAuth2Discovery, error) {
	result := &adminv1.OAuth2Discovery{}

	provider := "http://127.0.0.1:8080/builtin/admin/api/v1/oatuh2"

	result.Issuer = provider
	result.AuthorizationEndpoint = provider + "/authorize"
	result.TokenEndpoint = provider + "/token"
	result.JwksUri = provider + "/certs"

	result.ResponseTypesSupported = []string{"none"}
	result.SubjectTypesSupported = []string{"public"}
	result.IdTokenSigningAlgValuesSupported = []string{"RS256"}

	return result, nil
}

// GetOAuth2Certs 获取内置 OpenID 公钥
func (a *KnownAdminAPI) GetOAuth2Certs(ctx context.Context, req *emptypb.Empty) (*adminv1.OAuth2Certs, error) {
	result := &adminv1.OAuth2Certs{}

	return result, nil
}
