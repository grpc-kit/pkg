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
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/menus"
	"github.com/grpc-kit/pkg/lion/policies"
	"github.com/grpc-kit/pkg/lion/principalroles"
	"github.com/grpc-kit/pkg/lion/rolemenus"
	"github.com/grpc-kit/pkg/lion/rolepolicies"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/usermemberships"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/protobuf/types/known/emptypb"
)

type builtinMenuSeed struct {
	Code        string
	DisplayName string
	RoutePath   string
	Icon        string
	SortOrder   int
	Protected   bool
	Children    []builtinMenuSeed
}

func builtinMenuSeeds() []builtinMenuSeed {
	seeds := []builtinMenuSeed{
		{
			Code:        "root",
			DisplayName: "根目录",
			RoutePath:   "/",
			SortOrder:   1,
			Children: []builtinMenuSeed{
				{
					Code:        "admin",
					DisplayName: "管理后台",
					RoutePath:   "/",
					SortOrder:   100,
					Children: []builtinMenuSeed{
						{
							Code:        "admin.user",
							DisplayName: "个人中心",
							RoutePath:   "/user",
							Icon:        "UserOutlined",
							SortOrder:   100,
							Children: []builtinMenuSeed{
								{
									Code:        "admin.user.profile",
									DisplayName: "我的信息",
									RoutePath:   "/user/profile",
									SortOrder:   100,
								},
							},
						},
						{
							Code:        "admin.setting",
							DisplayName: "系统设置",
							RoutePath:   "/setting",
							Icon:        "SettingOutlined",
							SortOrder:   200,
							Children: []builtinMenuSeed{
								{
									Code:        "admin.setting.auth",
									DisplayName: "身份认证",
									RoutePath:   "/setting/auth",
									SortOrder:   100,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.auth.providers", DisplayName: "认证提供方", RoutePath: "/setting/auth/providers", SortOrder: 100},
										{Code: "admin.setting.auth.oauth2-clients", DisplayName: "OAuth2 客户端", RoutePath: "/setting/auth/oauth2-clients", SortOrder: 200},
									},
								},
								{
									Code:        "admin.setting.departments",
									DisplayName: "部门管理",
									RoutePath:   "/setting/departments",
									SortOrder:   200,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.departments.detail", DisplayName: "部门详情", RoutePath: "/setting/departments/detail", SortOrder: 100},
									},
								},
								{
									Code:        "admin.setting.menus",
									DisplayName: "菜单管理",
									RoutePath:   "/setting/menus",
									SortOrder:   300,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.menus.list", DisplayName: "菜单列表", RoutePath: "/setting/menus/list", SortOrder: 100},
									},
								},
								{
									Code:        "admin.setting.roles",
									DisplayName: "角色管理",
									RoutePath:   "/setting/roles",
									SortOrder:   400,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.roles.list", DisplayName: "角色列表", RoutePath: "/setting/roles/list", SortOrder: 100},
									},
								},
								{
									Code:        "admin.setting.policies",
									DisplayName: "权限策略",
									RoutePath:   "/setting/policies",
									SortOrder:   500,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.policies.list", DisplayName: "策略列表", RoutePath: "/setting/policies/list", SortOrder: 100},
										{Code: "admin.setting.policies.create", DisplayName: "新建策略", RoutePath: "/setting/policies/create", SortOrder: 200},
									},
								},
								{
									Code:        "admin.setting.groups",
									DisplayName: "群组管理",
									RoutePath:   "/setting/groups",
									SortOrder:   600,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.groups.list", DisplayName: "群组列表", RoutePath: "/setting/groups/list", SortOrder: 100},
									},
								},
								{
									Code:        "admin.setting.users",
									DisplayName: "用户管理",
									RoutePath:   "/setting/users",
									SortOrder:   700,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.users.list", DisplayName: "用户列表", RoutePath: "/setting/users/list", SortOrder: 100},
									},
								},
								{Code: "admin.setting.global-settings", DisplayName: "全局设置", RoutePath: "/setting/global-settings", SortOrder: 800},

								{
									Code:        "admin.setting.config",
									DisplayName: "本地配置",
									RoutePath:   "/setting/config",
									SortOrder:   900,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.config.security", DisplayName: "认证鉴权", RoutePath: "/setting/config/security", SortOrder: 100},
										{Code: "admin.setting.config.services", DisplayName: "基础服务", RoutePath: "/setting/config/services", SortOrder: 200},
										{Code: "admin.setting.config.discover", DisplayName: "服务发现", RoutePath: "/setting/config/discover", SortOrder: 300},
										{Code: "admin.setting.config.database", DisplayName: "关系存储", RoutePath: "/setting/config/database", SortOrder: 400},
										{Code: "admin.setting.config.cachebox", DisplayName: "缓存服务", RoutePath: "/setting/config/cachebox", SortOrder: 500},
										{Code: "admin.setting.config.debugger", DisplayName: "日志调试", RoutePath: "/setting/config/debugger", SortOrder: 600},
										{Code: "admin.setting.config.objstore", DisplayName: "对象存储", RoutePath: "/setting/config/objstore", SortOrder: 700},
										{Code: "admin.setting.config.frontend", DisplayName: "前端托管", RoutePath: "/setting/config/frontend", SortOrder: 800},
										{Code: "admin.setting.config.observables", DisplayName: "可观测性", RoutePath: "/setting/config/observables", SortOrder: 900},
										{Code: "admin.setting.config.cloudevents", DisplayName: "消息事件", RoutePath: "/setting/config/cloudevents", SortOrder: 1000},
										{Code: "admin.setting.config.automations", DisplayName: "流程编排", RoutePath: "/setting/config/automations", SortOrder: 1100},
										{Code: "admin.setting.config.independent", DisplayName: "独立配置", RoutePath: "/setting/config/independent", SortOrder: 1200},
									},
								},
							},
						},
						{
							Code:        "admin.apidocs",
							DisplayName: "API 文档",
							RoutePath:   "/apidocs",
							Icon:        "SolutionOutlined",
							SortOrder:   300,
							Children: []builtinMenuSeed{
								{
									Code:        "admin.apidocs.service",
									DisplayName: "服务文档",
									RoutePath:   "/apidocs/service",
									SortOrder:   100,
								},
							},
						},
					},
				},
				{
					Code:        "portal",
					DisplayName: "用户门户",
					RoutePath:   "/portal",
					SortOrder:   200,
					Children: []builtinMenuSeed{
						{
							Code:        "portal.home",
							DisplayName: "主页",
							RoutePath:   "/portal/home",
							Icon:        "HomeOutlined",
							SortOrder:   100,
						},
					},
				},
				{
					Code:        "miniapp",
					DisplayName: "小程序",
					RoutePath:   "/miniapp",
					SortOrder:   300,
					Children: []builtinMenuSeed{
						{
							Code:        "miniapp.home",
							DisplayName: "主页",
							RoutePath:   "/miniapp/home",
							Icon:        "HomeOutlined",
							SortOrder:   100,
						},
					},
				},
				{
					Code:        "mobile",
					DisplayName: "移动端",
					RoutePath:   "/mobile",
					SortOrder:   400,
					Children: []builtinMenuSeed{
						{
							Code:        "mobile.home",
							DisplayName: "主页",
							RoutePath:   "/mobile/home",
							Icon:        "HomeOutlined",
							SortOrder:   100,
						},
					},
				},
			},
		},
	}
	markMenuSeedsProtected(seeds)
	return seeds
}

// markMenuSeedsProtected 递归标记所有内置菜单种子为受保护项。
func markMenuSeedsProtected(seeds []builtinMenuSeed) {
	for i := range seeds {
		seeds[i].Protected = true
		markMenuSeedsProtected(seeds[i].Children)
	}
}

func createBuiltinMenus(ctx context.Context, tx *lion.Tx, parentID int64, items []builtinMenuSeed) error {
	for _, item := range items {
		obj, err := tx.Menus.Query().Where(menus.CodeEQ(item.Code)).Only(ctx)
		if lion.IsNotFound(err) {
			obj, err = tx.Menus.Create().
				SetParentID(parentID).
				SetCode(item.Code).
				SetDisplayName(item.DisplayName).
				SetRoutePath(item.RoutePath).
				SetComponent("").
				SetIcon(item.Icon).
				SetSortOrder(item.SortOrder).
				SetVisibility("global").
				SetDescription("").
				SetProtected(item.Protected).
				Save(ctx)
			if err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else {
			obj, err = obj.Update().
				SetParentID(parentID).
				SetDisplayName(item.DisplayName).
				SetRoutePath(item.RoutePath).
				SetIcon(item.Icon).
				SetSortOrder(item.SortOrder).
				SetProtected(item.Protected).
				Save(ctx)
			if err != nil {
				return err
			}
		}
		if err := createBuiltinMenus(ctx, tx, int64(obj.ID), item.Children); err != nil {
			return err
		}
	}
	return nil
}

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

	superadminPolicyCode := "superadmin-full-access"
	superadminPolicy, err := tx.Policies.Query().Where(policies.CodeEQ(superadminPolicyCode)).Only(ctx)
	if lion.IsNotFound(err) {
		superadminPolicy, err = tx.Policies.Create().
			SetCode(superadminPolicyCode).
			SetDisplayName("超级管理员全量策略").
			SetPolicyStatus(int(adminv1.Policy_ENABLED)).
			SetProtected(true).
			SetDescription("系统内置超级管理员全量访问策略").
			SetStatements([]*adminv1.PolicyStatement{{
				Effect:    adminv1.PolicyStatement_ALLOW,
				Actions:   []string{"*"},
				Resources: []string{"*"},
			}}).
			Save(ctx)
		if err != nil {
			rollback()
			return nil, err
		}
	} else if err != nil {
		rollback()
		return nil, err
	}

	rolePolicyExists, err := tx.RolePolicies.Query().
		Where(rolepolicies.RoleIDEQ(adminRole.ID), rolepolicies.PolicyIDEQ(superadminPolicy.ID)).
		Exist(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	if !rolePolicyExists {
		if err := tx.RolePolicies.Create().
			SetRoleID(adminRole.ID).
			SetPolicyID(superadminPolicy.ID).
			SetDescription("初始化绑定：超级管理员默认全量策略").
			Exec(ctx); err != nil {
			rollback()
			return nil, err
		}
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

	userRoleExists, err := tx.PrincipalRoles.Query().
		Where(
			principalroles.PrincipalTypeEQ(principalTypeUser),
			principalroles.PrincipalIDEQ(adminUser.ID),
			principalroles.RoleIDEQ(adminRole.ID),
		).
		Exist(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	if !userRoleExists {
		if err := tx.PrincipalRoles.Create().
			SetPrincipalType(principalTypeUser).
			SetPrincipalID(adminUser.ID).
			SetRoleID(adminRole.ID).
			SetBindingStatus(bindingStatusActive).
			Exec(ctx); err != nil {
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
			SetCreatedBy(int64(adminUser.ID)).
			SetUpdatedBy(int64(adminUser.ID)).
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

	if err := ensureGlobalSettingsSeeds(ctx, tx); err != nil {
		rollback()
		return nil, err
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
			SetDisplayName("根部门").
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
	} else {
		if err := rootDept.Update().
			SetDisplayName("根部门").
			SetProtected(true).
			Exec(ctx); err != nil {
			rollback()
			return nil, err
		}
	}

	builtinDept, err := tx.Departments.Query().
		Where(
			departments.CodeEQ("builtin"),
			departments.ParentIDEQ(rootDept.ID),
		).
		Only(ctx)
	if lion.IsNotFound(err) {
		// 兼容旧种子：如果已存在 legacy system 部门，则原位迁移为 builtin。
		builtinDept, err = tx.Departments.Query().
			Where(
				departments.CodeEQ("system"),
				departments.ParentIDEQ(rootDept.ID),
			).
			Only(ctx)
		if lion.IsNotFound(err) {
			builtinDept, err = tx.Departments.Create().
				SetParentID(rootDept.ID).
				SetCode("builtin").
				SetDisplayName("内置部门").
				SetSortOrder(1).
				SetProtected(true).
				Save(ctx)
			if err != nil {
				rollback()
				return nil, err
			}
		} else if err != nil {
			rollback()
			return nil, err
		} else {
			if err := builtinDept.Update().
				SetParentID(rootDept.ID).
				SetCode("builtin").
				SetDisplayName("内置部门").
				SetSortOrder(1).
				SetProtected(true).
				Exec(ctx); err != nil {
				rollback()
				return nil, err
			}
		}
	} else if err != nil {
		rollback()
		return nil, err
	} else {
		if err := builtinDept.Update().
			SetParentID(rootDept.ID).
			SetCode("builtin").
			SetDisplayName("内置部门").
			SetSortOrder(1).
			SetProtected(true).
			Exec(ctx); err != nil {
			rollback()
			return nil, err
		}
	}

	adminDept, err := tx.Departments.Query().
		Where(
			departments.CodeEQ("admin"),
			departments.ParentIDEQ(builtinDept.ID),
		).
		Only(ctx)
	if lion.IsNotFound(err) {
		adminDept, err = tx.Departments.Query().
			Where(
				departments.CodeEQ("admin"),
				departments.ParentIDEQ(rootDept.ID),
			).
			Only(ctx)
		if lion.IsNotFound(err) {
			adminDept, err = tx.Departments.Create().
				SetParentID(builtinDept.ID).
				SetCode("admin").
				SetDisplayName("管理员部门").
				SetSortOrder(1).
				SetProtected(true).
				Save(ctx)
			if err != nil {
				rollback()
				return nil, err
			}
		} else if err != nil {
			rollback()
			return nil, err
		} else {
			if err := adminDept.Update().
				SetParentID(builtinDept.ID).
				SetDisplayName("管理员部门").
				SetSortOrder(1).
				SetProtected(true).
				Exec(ctx); err != nil {
				rollback()
				return nil, err
			}
		}
	} else if err != nil {
		rollback()
		return nil, err
	} else {
		if err := adminDept.Update().
			SetParentID(builtinDept.ID).
			SetDisplayName("管理员部门").
			SetSortOrder(1).
			SetProtected(true).
			Exec(ctx); err != nil {
			rollback()
			return nil, err
		}
	}

	adminDeptMember, err := tx.UserMemberships.Query().
		Where(
			usermemberships.UserIDEQ(adminUser.ID),
			usermemberships.TargetTypeEQ(membershipTargetDepartment),
			usermemberships.TargetIDEQ(adminDept.ID),
		).
		Only(ctx)
	if lion.IsNotFound(err) {
		if err := tx.UserMemberships.Create().
			SetUserID(adminUser.ID).
			SetTargetType(membershipTargetDepartment).
			SetTargetID(adminDept.ID).
			SetMemberType(int(adminv1.Membership_PRIMARY.Number())).
			SetMemberRole(int(adminv1.Membership_OWNER.Number())).
			SetMemberStatus(int(adminv1.Membership_ACTIVE.Number())).
			Exec(ctx); err != nil {
			rollback()
			return nil, err
		}
	} else if err != nil {
		rollback()
		return nil, err
	} else {
		if err := adminDeptMember.Update().
			SetMemberType(int(adminv1.Membership_PRIMARY.Number())).
			SetMemberRole(int(adminv1.Membership_OWNER.Number())).
			SetMemberStatus(int(adminv1.Membership_ACTIVE.Number())).
			Exec(ctx); err != nil {
			rollback()
			return nil, err
		}
	}

	guestCode := seedDepartmentCode(adminv1.DepartmentCode_DEPARTMENT_CODE_GUEST)
	guestDept, err := tx.Departments.Query().
		Where(
			departments.CodeEQ(guestCode),
			departments.ParentIDEQ(builtinDept.ID),
		).
		Only(ctx)
	if lion.IsNotFound(err) {
		guestDept, err = tx.Departments.Query().
			Where(
				departments.CodeEQ(guestCode),
				departments.ParentIDEQ(rootDept.ID),
			).
			Only(ctx)
		if lion.IsNotFound(err) {
			guestDept, err = tx.Departments.Create().
				SetParentID(builtinDept.ID).
				SetCode(guestCode).
				SetDisplayName("访客部门").
				SetSortOrder(2).
				SetProtected(true).
				Save(ctx)
			if err != nil {
				rollback()
				return nil, err
			}
		} else if err != nil {
			rollback()
			return nil, err
		} else {
			if err := guestDept.Update().
				SetParentID(builtinDept.ID).
				SetDisplayName("访客部门").
				SetSortOrder(2).
				SetProtected(true).
				Exec(ctx); err != nil {
				rollback()
				return nil, err
			}
		}
	} else if err != nil {
		rollback()
		return nil, err
	} else {
		if err := guestDept.Update().
			SetParentID(builtinDept.ID).
			SetDisplayName("访客部门").
			SetSortOrder(2).
			SetProtected(true).
			Exec(ctx); err != nil {
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

	if err := createBuiltinMenus(ctx, tx, 0, builtinMenuSeeds()); err != nil {
		rollback()
		return nil, err
	}

	rootMenu, err := tx.Menus.Query().Where(menus.CodeEQ("root")).Only(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	roleMenuExists, err := tx.RoleMenus.Query().
		Where(rolemenus.RoleIDEQ(adminRole.ID), rolemenus.MenuIDEQ(rootMenu.ID)).
		Exist(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	if !roleMenuExists {
		if err := tx.RoleMenus.Create().
			SetRoleID(adminRole.ID).
			SetMenuID(rootMenu.ID).
			SetPermissionScope(1).
			SetIsRecursive(true).
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
