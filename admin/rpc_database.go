package admin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"strconv"

	"github.com/google/uuid"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
	"github.com/grpc-kit/pkg/lion/credentials"
	"github.com/grpc-kit/pkg/lion/departmentmembers"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/menus"
	"github.com/grpc-kit/pkg/lion/resources"
	"github.com/grpc-kit/pkg/lion/resourcetypes"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/services"
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

	serviceCode := a.defaultServiceCode()
	serviceObj, err := tx.Services.Query().Where(services.CodeEQ(serviceCode)).Only(ctx)
	if lion.IsNotFound(err) {
		serviceObj, err = tx.Services.Create().
			SetCode(serviceCode).
			SetGrpcName("default.api.oneops.admin.v1.OneopsAdmin").
			SetDisplayName("Admin 管理服务").
			SetDescription("系统初始化创建的默认服务字典").
			SetProtected(true).
			Save(ctx)
	} else if err != nil {
		rollback()
		return nil, err
	}
	if err != nil {
		rollback()
		return nil, err
	}

	resourceTypeCatalog := map[string]*lion.ResourceTypes{}
	for _, seed := range []struct {
		code, displayName string
	}{
		{code: "sys_menu", displayName: "系统菜单"},
		{code: "sys_api", displayName: "系统 API"},
		{code: "sys_object", displayName: "系统对象"},
	} {
		obj, qErr := tx.ResourceTypes.Query().Where(resourcetypes.CodeEQ(seed.code)).Only(ctx)
		if lion.IsNotFound(qErr) {
			obj, qErr = tx.ResourceTypes.Create().
				SetCode(seed.code).
				SetDisplayName(seed.displayName).
				SetServiceCode(serviceObj.Code).
				SetDescription("系统初始化创建的默认资源类型").
				SetProtected(true).
				Save(ctx)
		}
		if qErr != nil {
			rollback()
			return nil, qErr
		}
		resourceTypeCatalog[seed.code] = obj
	}

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

	rootResourceSeeds := []struct {
		seedCode adminv1.ResourceSeedCode
		name     string
		resType  adminv1.Resource_Type
		sort     int
	}{
		{adminv1.ResourceSeedCode_RESOURCE_SEED_CODE_ROOT_MENU, "菜单根节点", adminv1.Resource_MENU, 10},
		{adminv1.ResourceSeedCode_RESOURCE_SEED_CODE_ROOT_DOMAIN, "领域根节点", adminv1.Resource_DOMAIN, 20},
		{adminv1.ResourceSeedCode_RESOURCE_SEED_CODE_ROOT_LLM, "LLM 根节点", adminv1.Resource_LLM, 30},
		{adminv1.ResourceSeedCode_RESOURCE_SEED_CODE_ROOT_API, "接口根节点", adminv1.Resource_API, 40},
		{adminv1.ResourceSeedCode_RESOURCE_SEED_CODE_ROOT_DATA, "数据根节点", adminv1.Resource_DATA, 50},
		{adminv1.ResourceSeedCode_RESOURCE_SEED_CODE_ROOT_SYSTEM, "系统根节点", adminv1.Resource_SYSTEM, 60},
	}
	for _, rs := range rootResourceSeeds {
		resType := int(rs.resType.Number())
		resourceTypeCode := resourceTypeCodeFromLegacy(resType)
		resourceTypeObj := resourceTypeCatalog[resourceTypeCode]
		exists, qerr := tx.Resources.Query().Where(
			resources.ParentIDEQ(0),
			resources.Or(
				resources.ResourceTypeIDEQ(resourceTypeObj.ID),
				resources.ResourceTypeEQ(resType),
			),
		).Exist(ctx)
		if qerr != nil {
			rollback()
			return nil, qerr
		}
		if exists {
			continue
		}
		if _, err := tx.Resources.Create().
			SetCode(seedResourceSeedCode(rs.seedCode)).
			SetName(fmt.Sprintf("grn:%s:::%s/root", serviceCode, resourceTypeCode)).
			SetDisplayName(rs.name).
			SetResourceType(resType).
			SetResourceTypeID(resourceTypeObj.ID).
			SetResourceTypeCode(resourceTypeObj.Code).
			SetServiceCode(serviceCode).
			SetResourcePath("root").
			SetGrn(fmt.Sprintf("grn:%s:::%s/root", serviceCode, resourceTypeCode)).
			SetResourceStatus(int(adminv1.Resource_ENABLED.Number())).
			SetResourceStatusCode("active").
			SetVisibility(int(adminv1.Visibility_VISIBILITY_GLOBAL.Number())).
			SetSortOrder(rs.sort).
			SetParentID(0).
			Save(ctx); err != nil {
			rollback()
			return nil, err
		}
	}

	_, err = seedBuiltinMenuTreeResources(ctx, tx, rollback, serviceCode, resourceTypeCatalog["sys_menu"])
	if err != nil {
		return nil, err
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

// seedParentMenuRoot 表示挂在 parent_id=0 的 MENU 类型根节点下（与 ResourceSeedCode 根菜单 code 一致）。
const seedParentMenuRoot = "__menu_root__"

// seedBuiltinMenuTreeResources 幂等补全内置菜单/页面资源（与常见 lion_resources 种子数据对齐）。
// 返回值为资源 code -> id，含菜单类型根节点，供后续菜单资源初始化复用。
func seedBuiltinMenuTreeResources(ctx context.Context, tx *lion.Tx, rollback func(), serviceCode string, menuResourceType *lion.ResourceTypes) (map[string]int, error) {
	menuRoot, err := tx.Resources.Query().Where(
		resources.ParentIDEQ(0),
		resources.Or(
			resources.ResourceTypeCodeEQ("sys_menu"),
			resources.ResourceTypeEQ(int(adminv1.Resource_MENU.Number())),
		),
	).Only(ctx)
	if err != nil {
		rollback()
		return nil, err
	}

	menuRootCode := seedResourceSeedCode(adminv1.ResourceSeedCode_RESOURCE_SEED_CODE_ROOT_MENU)
	idByCode := map[string]int{menuRootCode: menuRoot.ID}
	menuIDByCode := map[string]int{}
	resourceTypeObj := menuResourceType

	type builtinMenuResource struct {
		code, displayName, parentRef string
		resType                      adminv1.Resource_Type
		sort                         int
		locator, visual              string
		protected                    bool
	}
	seeds := []builtinMenuResource{
		{"user", "个人中心", seedParentMenuRoot, adminv1.Resource_MENU, 2, "/user", "UserOutlined", true},
		{"profile", "我的信息", "user", adminv1.Resource_MENU, 7, "/user/profile", "", true},
		{"setting", "系统设置", seedParentMenuRoot, adminv1.Resource_MENU, 9, "/setting", "SettingOutlined", true},
		{"auth-providers", "身份认证", "setting", adminv1.Resource_MENU, 100, "/setting/authentications", "", true},
		{"departments", "组织架构", "setting", adminv1.Resource_MENU, 200, "/setting/departments", "", true},
		{"roles", "角色管理", "setting", adminv1.Resource_MENU, 300, "/setting/roles", "", true},
		{"resources", "资源管理", "setting", adminv1.Resource_MENU, 400, "/setting/resources", "", true},
		{"permissions", "权限管理", "setting", adminv1.Resource_MENU, 500, "/setting/permissions", "", true},
		{"groups", "群组管理", "setting", adminv1.Resource_MENU, 600, "/setting/groups", "", true},
		{"users", "用户管理", "setting", adminv1.Resource_MENU, 700, "/setting/users", "", true},
		{"config", "配置管理", "setting", adminv1.Resource_MENU, 900, "/setting/config", "", true},
	}

	visUnspecified := int(adminv1.Visibility_VISIBILITY_UNSPECIFIED.Number())
	enabled := int(adminv1.Resource_ENABLED.Number())

	for _, s := range seeds {
		var parentID int64
		switch s.parentRef {
		case seedParentMenuRoot:
			parentID = int64(menuRoot.ID)
		default:
			pid, ok := idByCode[s.parentRef]
			if !ok {
				rollback()
				return nil, fmt.Errorf("builtin resource seed: unknown parent code %q", s.parentRef)
			}
			parentID = int64(pid)
		}

		exists, err := tx.Resources.Query().Where(
			resources.CodeEQ(s.code),
			resources.ParentIDEQ(parentID),
		).Exist(ctx)
		if err != nil {
			rollback()
			return nil, err
		}
		if exists {
			row, err := tx.Resources.Query().Where(
				resources.CodeEQ(s.code),
				resources.ParentIDEQ(parentID),
			).Only(ctx)
			if err != nil {
				rollback()
				return nil, err
			}
			if s.protected && !row.Protected {
				if err := tx.Resources.UpdateOneID(row.ID).SetProtected(true).Exec(ctx); err != nil {
					rollback()
					return nil, err
				}
			}
			idByCode[s.code] = row.ID

			menuParentID := int64(0)
			if s.parentRef != seedParentMenuRoot {
				if parentMenuID, ok := menuIDByCode[s.parentRef]; ok {
					menuParentID = int64(parentMenuID)
				}
			}
			menuRow, err := tx.Menus.Query().Where(menus.CodeEQ(s.code), menus.ParentIDEQ(menuParentID)).Only(ctx)
			if lion.IsNotFound(err) {
				menuRow, err = tx.Menus.Create().
					SetParentID(menuParentID).
					SetResourceID(row.ID).
					SetCode(s.code).
					SetDisplayName(s.displayName).
					SetRoutePath(s.locator).
					SetIcon(s.visual).
					SetSortOrder(s.sort).
					SetSurfaceMask(1).
					SetVisibility("full").
					SetMenuStatus("active").
					Save(ctx)
			}
			if err != nil {
				rollback()
				return nil, err
			}
			menuIDByCode[s.code] = menuRow.ID
			continue
		}

		grn := buildResourceGRN(serviceCode, "", "", resourceTypeObj.Code, normalizeResourcePath("", s.code, s.locator), "")
		row, err := tx.Resources.Create().
			SetCode(s.code).
			SetName(grn).
			SetDisplayName(s.displayName).
			SetResourceType(int(s.resType.Number())).
			SetResourceTypeID(resourceTypeObj.ID).
			SetResourceTypeCode(resourceTypeObj.Code).
			SetServiceCode(serviceCode).
			SetResourcePath(normalizeResourcePath("", s.code, s.locator)).
			SetGrn(grn).
			SetResourceStatus(enabled).
			SetResourceStatusCode("active").
			SetVisibility(visUnspecified).
			SetSortOrder(s.sort).
			SetParentID(parentID).
			SetLocator(s.locator).
			SetVisual(s.visual).
			SetProtected(s.protected).
			Save(ctx)
		if err != nil {
			rollback()
			return nil, err
		}
		idByCode[s.code] = row.ID

		menuParentID := int64(0)
		if s.parentRef != seedParentMenuRoot {
			if parentMenuID, ok := menuIDByCode[s.parentRef]; ok {
				menuParentID = int64(parentMenuID)
			}
		}
		menuRow, err := tx.Menus.Query().Where(menus.CodeEQ(s.code), menus.ParentIDEQ(menuParentID)).Only(ctx)
		if lion.IsNotFound(err) {
			menuRow, err = tx.Menus.Create().
				SetParentID(menuParentID).
				SetResourceID(row.ID).
				SetCode(s.code).
				SetDisplayName(s.displayName).
				SetRoutePath(s.locator).
				SetIcon(s.visual).
				SetSortOrder(s.sort).
				SetSurfaceMask(1).
				SetVisibility("full").
				SetMenuStatus("active").
				Save(ctx)
		}
		if err != nil {
			rollback()
			return nil, err
		}
		menuIDByCode[s.code] = menuRow.ID
	}
	return idByCode, nil
}
