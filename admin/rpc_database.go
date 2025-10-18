package admin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strconv"

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

	// 为 users 表 id 默认从 654321 开始

	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}

	adminUser, err := tx.Users.Create().
		SetUsername("admin").
		SetUserType(int(adminv1.User_TYPE_SYSTEM.Number())).
		SetUserStatus(int(adminv1.User_STATUS_ACTIVE.Number())).
		SetNickname("超级管理员").
		SetDescription("初始超级管理员，系统配置成功后建议删除或者禁用！").
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return result, err
	}

	adminRole, err := tx.Roles.Create().
		SetName("superadmin").
		SetRoleType(int(adminv1.Role_TYPE_SYSTEM.Number())).
		SetDescription("超级管理员").
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return result, err
	}

	tx.UserRoles.Create().SetUserID(adminUser.ID).SetRoleID(adminRole.ID).SaveX(ctx)

	localProvider, err := tx.AuthProviders.Create().
		SetName("local").
		SetProviderType(int(adminv1.AuthProvider_TYPE_LOCAL.Number())).
		SetEnabled(true).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return result, err
	}

	tx.UserIdentities.Create().
		SetProviderID(localProvider.ID).
		SetProviderUserID(strconv.Itoa(adminUser.ID)).
		SetUserID(adminUser.ID).
		SetPasswordHash(crypto.BcryptHashMust(crypto.SHA256([]byte("grpc-kit-cli")))). // TODO; 由客户端参数获取
		SaveX(ctx)

	tx.Departments.CreateBulk(
		tx.Departments.Create().
			SetName("root").
			SetSortOrder(1).
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
		SetCredentialType(int(adminv1.Credential_TYPE_JWKS.Number())).
		SetCredentialAlgorithm(int(adminv1.Credential_ALGORITHM_RSA.Number())).
		SetCredentialUsage(int(adminv1.Credential_USAGE_SIGNING.Number())).
		SetCredentialVisibility(int(adminv1.Credential_VISIBILITY_PRIVATE.Number())).
		SetCredentialStatus(int(adminv1.Credential_STATUS_ACTIVE.Number())).
		SetCredentialSource(int(adminv1.Credential_SOURCE_SYSTEM.Number())).
		SetKeyID(uuid.New().String()).
		SetPublicKey(crypto.Base64Encode(publicKeyBytes)).
		SetPrivateKeyEncrypted(privateKeyEnc).
		SaveX(ctx)

	tx.Commit()

	return result, nil
}
