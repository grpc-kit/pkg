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
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
	"github.com/grpc-kit/pkg/lion/credentials"
	"github.com/grpc-kit/pkg/lion/departmentmembers"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/userroles"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/protobuf/types/known/emptypb"
)

// CreateDatabaseInitialize 幂等补全内置种子数据：已存在则跳过，缺失则创建。
func (a *KnownAdminAPI) CreateDatabaseInitialize(ctx context.Context, req *adminv1.CreateDatabaseInitializeRequest) (*emptypb.Empty, error) {
	result := &emptypb.Empty{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	rollback := func() { _ = tx.Rollback() }

	superadminCode := seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN)
	adminRole, err := tx.Roles.Query().Where(roles.CodeEQ(superadminCode)).Only(ctx)
	if lion.IsNotFound(err) {
		adminRole, err = tx.Roles.Create().
			SetCode(superadminCode).
			SetDisplayName(superadminCode).
			SetRoleType(int(adminv1.Role_SYSTEM.Number())).
			SetDescription("超级管理员").
			Save(ctx)
		if err != nil {
			rollback()
			return nil, err
		}
	} else if err != nil {
		rollback()
		return nil, err
	}

	adminUsername := seedBootstrapUsername(adminv1.BootstrapUsername_BOOTSTRAP_USERNAME_ADMIN)
	adminUser, err := tx.Users.Query().Where(users.UsernameEQ(adminUsername)).Only(ctx)
	if lion.IsNotFound(err) {
		adminUser, err = tx.Users.Create().
			SetUsername(adminUsername).
			SetUserType(int(adminv1.User_SYSTEM.Number())).
			SetUserStatus(int(adminv1.User_ACTIVE.Number())).
			SetNickname("超级管理员").
			SetDescription("初始超级管理员，系统配置成功后建议删除或者禁用！").
			Save(ctx)
		if err != nil {
			rollback()
			return nil, err
		}
	} else if err != nil {
		rollback()
		return nil, err
	}

	userRoleExists, err := tx.UserRoles.Query().
		Where(userroles.UserIDEQ(adminUser.ID), userroles.RoleIDEQ(adminRole.ID)).
		Exist(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	if !userRoleExists {
		if err := tx.UserRoles.Create().SetUserID(adminUser.ID).SetRoleID(adminRole.ID).Exec(ctx); err != nil {
			rollback()
			return nil, err
		}
	}

	localCode := seedAuthProviderCode(adminv1.AuthProviderCode_AUTH_PROVIDER_CODE_LOCAL)
	localProvider, err := tx.AuthProviders.Query().Where(authproviders.CodeEQ(localCode)).Only(ctx)
	if lion.IsNotFound(err) {
		localProvider, err = tx.AuthProviders.Create().
			SetCode(localCode).
			SetProviderType(int(adminv1.AuthProvider_LOCAL.Number())).
			SetProviderStatus(int(adminv1.AuthProvider_ACTIVE.Number())).
			SetDisplayName("本地账号密码登录").
			SetSortOrder(100).
			SetProtected(true).
			Save(ctx)
		if err != nil {
			rollback()
			return nil, err
		}
	} else if err != nil {
		rollback()
		return nil, err
	}

	identityExists, err := tx.UserIdentities.Query().
		Where(useridentities.UserIDEQ(adminUser.ID), useridentities.ProviderIDEQ(localProvider.ID)).
		Exist(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	if !identityExists {
		if err := tx.UserIdentities.Create().
			SetProviderID(localProvider.ID).
			SetProviderUserID(strconv.Itoa(adminUser.ID)).
			SetUserID(adminUser.ID).
			SetPasswordHash(crypto.BcryptHashMust(crypto.SHA256([]byte("grpc-kit-cli")))). // TODO; 由客户端参数获取
			Exec(ctx); err != nil {
			rollback()
			return nil, err
		}
	}

	rootCode := seedDepartmentCode(adminv1.DepartmentCode_DEPARTMENT_CODE_ROOT)
	rootDept, err := tx.Departments.Query().
		Where(
			departments.CodeEQ(rootCode),
			departments.ParentIDEQ(0),
		).
		Only(ctx)
	if lion.IsNotFound(err) {
		rootDept, err = tx.Departments.Create().
			SetCode(rootCode).
			SetDisplayName(rootCode).
			SetSortOrder(1).
			SetProtected(true).
			SetParentID(0).
			Save(ctx)
		if err != nil {
			rollback()
			return nil, err
		}
	} else if err != nil {
		rollback()
		return nil, err
	}

	rootDeptMemberExists, err := tx.DepartmentMembers.Query().
		Where(
			departmentmembers.UserIDEQ(adminUser.ID),
			departmentmembers.DepartmentIDEQ(rootDept.ID),
		).
		Exist(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	if !rootDeptMemberExists {
		if err := tx.DepartmentMembers.Create().
			SetUserID(adminUser.ID).
			SetDepartmentID(rootDept.ID).
			SetMemberType(int(adminv1.Membership_PRIMARY.Number())).
			SetMemberRole(int(adminv1.Membership_OWNER.Number())).
			SetMemberStatus(int(adminv1.Membership_ACTIVE.Number())).
			Exec(ctx); err != nil {
			rollback()
			return nil, err
		}
	}

	guestCode := seedDepartmentCode(adminv1.DepartmentCode_DEPARTMENT_CODE_GUEST)
	guestExists, err := tx.Departments.Query().
		Where(
			departments.CodeEQ(guestCode),
			departments.ParentIDEQ(rootDept.ID),
		).
		Exist(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	if !guestExists {
		if _, err := tx.Departments.Create().
			SetParentID(rootDept.ID).
			SetCode(guestCode).
			SetDisplayName(guestCode).
			SetSortOrder(2).
			SetProtected(true).
			Save(ctx); err != nil {
			rollback()
			return nil, err
		}
	}

	credCode := seedCredentialSeedCode(adminv1.CredentialSeedCode_CREDENTIAL_SEED_CODE_KEY1)
	credExists, err := tx.Credentials.Query().Where(
		credentials.CodeEQ(credCode),
		credentials.CredentialTypeEQ(int(adminv1.Credential_JWKS.Number())),
	).Exist(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	if !credExists {
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			rollback()
			return nil, err
		}
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			rollback()
			return nil, err
		}
		privateKeyEnc, err := crypto.EncryptAES(a.config.aesKey, privateKeyBytes)
		if err != nil {
			rollback()
			return nil, err
		}
		if err := tx.Credentials.Create().
			SetCode(credCode).
			SetCredentialType(int(adminv1.Credential_JWKS.Number())).
			SetCredentialAlgorithm(int(adminv1.Credential_RSA.Number())).
			SetCredentialUsage(int(adminv1.Credential_SIGNING.Number())).
			SetCredentialVisibility(int(adminv1.Visibility_VISIBILITY_RESTRICTED.Number())).
			SetCredentialStatus(int(adminv1.Credential_ACTIVE.Number())).
			SetCredentialSource(int(adminv1.Credential_SYSTEM.Number())).
			SetKeyID(uuid.New().String()).
			SetPublicKey(crypto.Base64Encode(publicKeyBytes)).
			SetPrivateKeyEncrypted(privateKeyEnc).
			Exec(ctx); err != nil {
			rollback()
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return result, nil
}
