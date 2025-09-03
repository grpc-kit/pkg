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
