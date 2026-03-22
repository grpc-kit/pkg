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
		SetUsername(seedBootstrapUsername(adminv1.BootstrapUsername_BOOTSTRAP_USERNAME_ADMIN)).
		SetUserType(int(adminv1.User_SYSTEM.Number())).
		SetUserStatus(int(adminv1.User_ACTIVE.Number())).
		SetNickname("超级管理员").
		SetDescription("初始超级管理员，系统配置成功后建议删除或者禁用！").
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return result, err
	}

	adminRole, err := tx.Roles.Create().
		SetCode(seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN)).
		SetDisplayName(seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN)).
		SetRoleType(int(adminv1.Role_SYSTEM.Number())).
		SetDescription("超级管理员").
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return result, err
	}

	tx.UserRoles.Create().SetUserID(adminUser.ID).SetRoleID(adminRole.ID).SaveX(ctx)

	localProvider, err := tx.AuthProviders.Create().
		SetCode(seedAuthProviderCode(adminv1.AuthProviderCode_AUTH_PROVIDER_CODE_LOCAL)).
		SetProviderType(int(adminv1.AuthProvider_LOCAL.Number())).
		SetProviderStatus(int(adminv1.AuthProvider_ACTIVE.Number())).
		SetDisplayName("本地账号密码登录").
		SetSortOrder(1).
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

	rootDept, err := tx.Departments.Create().
		SetCode(seedDepartmentCode(adminv1.DepartmentCode_DEPARTMENT_CODE_ROOT)).
		SetDisplayName(seedDepartmentCode(adminv1.DepartmentCode_DEPARTMENT_CODE_ROOT)).
		SetSortOrder(1).
		SetProtected(true).
		SetParentID(0).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return result, err
	}
	_, err = tx.Departments.Create().
		SetParentID(rootDept.ID).
		SetCode(seedDepartmentCode(adminv1.DepartmentCode_DEPARTMENT_CODE_GUEST)).
		SetDisplayName(seedDepartmentCode(adminv1.DepartmentCode_DEPARTMENT_CODE_GUEST)).
		SetSortOrder(2).
		SetProtected(true).
		Save(ctx)
	if err != nil {
		_ = tx.Rollback()
		return result, err
	}

	tx.Resources.CreateBulk(
		tx.Resources.Create().
			SetCode(seedResourceSeedCode(adminv1.ResourceSeedCode_RESOURCE_SEED_CODE_ROOT_MENU)).
			SetDisplayName("菜单根节点").
			SetResourceType(int(adminv1.Resource_MENU.Number())).
			SetResourceStatus(int(adminv1.Resource_ENABLED.Number())).
			SetVisibility(int(adminv1.Visibility_VISIBILITY_GLOBAL.Number())).
			SetSortOrder(10).
			SetParentID(0),
		tx.Resources.Create().
			SetCode(seedResourceSeedCode(adminv1.ResourceSeedCode_RESOURCE_SEED_CODE_ROOT_PAGE)).
			SetDisplayName("页面根节点").
			SetResourceType(int(adminv1.Resource_PAGE.Number())).
			SetResourceStatus(int(adminv1.Resource_ENABLED.Number())).
			SetVisibility(int(adminv1.Visibility_VISIBILITY_GLOBAL.Number())).
			SetSortOrder(20).
			SetParentID(0),
		tx.Resources.Create().
			SetCode(seedResourceSeedCode(adminv1.ResourceSeedCode_RESOURCE_SEED_CODE_ROOT_BUTTON)).
			SetDisplayName("按钮根节点").
			SetResourceType(int(adminv1.Resource_BUTTON.Number())).
			SetResourceStatus(int(adminv1.Resource_ENABLED.Number())).
			SetVisibility(int(adminv1.Visibility_VISIBILITY_GLOBAL.Number())).
			SetSortOrder(30).
			SetParentID(0),
		tx.Resources.Create().
			SetCode(seedResourceSeedCode(adminv1.ResourceSeedCode_RESOURCE_SEED_CODE_ROOT_API)).
			SetDisplayName("接口根节点").
			SetResourceType(int(adminv1.Resource_API.Number())).
			SetResourceStatus(int(adminv1.Resource_ENABLED.Number())).
			SetVisibility(int(adminv1.Visibility_VISIBILITY_GLOBAL.Number())).
			SetSortOrder(40).
			SetParentID(0),
		tx.Resources.Create().
			SetCode(seedResourceSeedCode(adminv1.ResourceSeedCode_RESOURCE_SEED_CODE_ROOT_DATA)).
			SetDisplayName("数据根节点").
			SetResourceType(int(adminv1.Resource_DATA.Number())).
			SetResourceStatus(int(adminv1.Resource_ENABLED.Number())).
			SetVisibility(int(adminv1.Visibility_VISIBILITY_GLOBAL.Number())).
			SetSortOrder(50).
			SetParentID(0),
		tx.Resources.Create().
			SetCode(seedResourceSeedCode(adminv1.ResourceSeedCode_RESOURCE_SEED_CODE_ROOT_SYSTEM)).
			SetDisplayName("系统根节点").
			SetResourceType(int(adminv1.Resource_SYSTEM.Number())).
			SetResourceStatus(int(adminv1.Resource_ENABLED.Number())).
			SetVisibility(int(adminv1.Visibility_VISIBILITY_GLOBAL.Number())).
			SetSortOrder(60).
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
		SetCode(seedCredentialSeedCode(adminv1.CredentialSeedCode_CREDENTIAL_SEED_CODE_KEY1)).
		SetCredentialType(int(adminv1.Credential_JWKS.Number())).
		SetCredentialAlgorithm(int(adminv1.Credential_RSA.Number())).
		SetCredentialUsage(int(adminv1.Credential_SIGNING.Number())).
		SetCredentialVisibility(int(adminv1.Visibility_VISIBILITY_RESTRICTED.Number())).
		SetCredentialStatus(int(adminv1.Credential_ACTIVE.Number())).
		SetCredentialSource(int(adminv1.Credential_SYSTEM.Number())).
		SetKeyID(uuid.New().String()).
		SetPublicKey(crypto.Base64Encode(publicKeyBytes)).
		SetPrivateKeyEncrypted(privateKeyEnc).
		SaveX(ctx)

	tx.Commit()

	return result, nil
}
