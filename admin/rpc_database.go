package admin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"

	"github.com/google/uuid"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion/roles"
	"google.golang.org/protobuf/types/known/emptypb"
)

// CreateDatabaseInitialize xx
func (a *KnownAdminAPI) CreateDatabaseInitialize(ctx context.Context, req *adminv1.CreateDatabaseInitializeRequest) (*emptypb.Empty, error) {
	result := &emptypb.Empty{}

	// 判断角色表是否有数据，否则认为首次部署，可以初始化数据

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	if count := db.Roles.Query().Select(roles.FieldID).CountX(ctx); count != 0 {
		return result, nil
	}

	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}

	tx.Roles.CreateBulk(
		tx.Roles.Create().
			SetName("superadmin").
			SetProtected(true).
			SetDescription("超级管理员"),
	).SaveX(ctx)

	tx.AuthProviders.CreateBulk(
		tx.AuthProviders.Create().
			SetName("local").
			SetType(int(adminv1.AuthProvider_TYPE_LOCAL.Number())).
			SetEnabled(true),
	).SaveX(ctx)

	tx.Departments.CreateBulk(
		tx.Departments.Create().
			SetName("root").
			/*
				SetI18nName(I18NNameJSON(&adminv1.I18NName{
					// DefaultLanguage: adminv1.LanguageCode_EN_US,
					Texts: []*adminv1.LocalizedText{
						{
							LanguageCode: adminv1.LanguageCode_ZH_CN,
							Text:         "根目录",
						},
						{
							LanguageCode: adminv1.LanguageCode_EN_US,
							Text:         "root",
						},
						{
							LanguageCode: adminv1.LanguageCode_JA_JP,
							Text:         "ルートディレクトリ",
						},
					},
				})).
			*/
			SetOrderWeight(1).
			SetParentID(0),
	).SaveX(ctx)

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
	tx.Credentials.Create().
		SetName("key1").
		SetType(int(adminv1.Credential_TYPE_JWKS.Number())).
		SetAppid(uuid.New().String()).
		SetUsage("sig").
		SetPublicKey(crypto.Base64Encode(publicKeyBytes)).
		SetPrivateKeyEncrypted(privateKeyEnc).SaveX(ctx)

	tx.Commit()

	return result, nil
}
