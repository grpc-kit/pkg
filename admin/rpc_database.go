package admin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"strconv"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
	"github.com/grpc-kit/pkg/lion/credentials"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/groups"
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

// defaultAdminPassword 是未通过请求参数指定时的初始管理员密码明文。
const defaultAdminPassword = "grpc-kit-cli"

// legacyGuestDepartmentCode 仅用于把旧版内置 guest 部门原位迁移为 unassigned。
const legacyGuestDepartmentCode = "guest"

type builtinRoleSeed struct {
	Code        string
	DisplayName string
	Description string
	ParentID    int
	SortOrder   int
}

type builtinGroupSeed struct {
	Code        string
	DisplayName string
	Description string
	UserFilter  string
	SortOrder   int
}

func ensureBuiltinGroup(ctx context.Context, tx *lion.Tx, seed builtinGroupSeed) (*lion.Groups, error) {
	protoGroup := &adminv1.Group{
		Code:        seed.Code,
		DisplayName: seed.DisplayName,
		Description: seed.Description,
		Type:        adminv1.Group_SYSTEM,
		Status:      adminv1.Group_ACTIVE,
		SortOrder:   int32(seed.SortOrder),
		Config: &adminv1.Group_SystemConfig_{SystemConfig: &adminv1.Group_SystemConfig{
			UserFilter: seed.UserFilter,
		}},
	}
	validated, err := validateGroupTypeConfig(ctx, tx.Client(), protoGroup, true)
	if err != nil {
		return nil, err
	}
	group, err := tx.Groups.Query().Where(groups.CodeEQ(seed.Code)).Only(ctx)
	if lion.IsNotFound(err) {
		if err := lockAndCheckActiveRuleGroupCapacity(ctx, tx, 1); err != nil {
			return nil, err
		}
		return tx.Groups.Create().
			SetCode(seed.Code).
			SetDisplayName(seed.DisplayName).
			SetGroupType(int(adminv1.Group_SYSTEM)).
			SetGroupStatus(int(adminv1.Group_ACTIVE)).
			SetSortOrder(seed.SortOrder).
			SetParentID(0).
			SetMaxMembers(0).
			SetConfig(validated.config).
			SetProtected(true).
			SetDescription(seed.Description).
			Save(ctx)
	}
	if err != nil {
		return nil, err
	}
	if adminv1.Group_Type(group.GroupType) != adminv1.Group_SYSTEM {
		return nil, errs.FailedPrecondition(ctx).WithMessage("built-in group code is occupied by a non-SYSTEM group")
	}
	if group.GroupStatus != int(adminv1.Group_ACTIVE) {
		if err := lockAndCheckActiveRuleGroupCapacity(ctx, tx, 1); err != nil {
			return nil, err
		}
	}
	return group.Update().
		SetDisplayName(seed.DisplayName).
		SetGroupType(int(adminv1.Group_SYSTEM)).
		SetGroupStatus(int(adminv1.Group_ACTIVE)).
		SetSortOrder(seed.SortOrder).
		SetParentID(0).
		SetMaxMembers(0).
		ClearSourceID().
		SetConfig(validated.config).
		SetProtected(true).
		SetDescription(seed.Description).
		Save(ctx)
}

func ensureBuiltinRole(ctx context.Context, tx *lion.Tx, seed builtinRoleSeed) (*lion.Roles, error) {
	role, err := tx.Roles.Query().Where(roles.CodeEQ(seed.Code)).Only(ctx)
	if lion.IsNotFound(err) {
		return tx.Roles.Create().
			SetParentID(seed.ParentID).
			SetCode(seed.Code).
			SetDisplayName(seed.DisplayName).
			SetRoleType(int(adminv1.Role_SYSTEM.Number())).
			SetRoleStatus(int(adminv1.Role_ACTIVE.Number())).
			SetSortOrder(seed.SortOrder).
			SetProtected(true).
			SetDescription(seed.Description).
			Save(ctx)
	}
	if err != nil {
		return nil, err
	}
	// 幂等收敛：内置角色 code 为保留值，已存在时按种子补齐属性
	// （ParentID/RoleType/Protected 等），不因历史属性不一致而报错退出，保证可重复执行。
	return role.Update().
		SetParentID(seed.ParentID).
		SetDisplayName(seed.DisplayName).
		SetRoleType(int(adminv1.Role_SYSTEM.Number())).
		SetRoleStatus(int(adminv1.Role_ACTIVE.Number())).
		SetSortOrder(seed.SortOrder).
		SetProtected(true).
		SetDescription(seed.Description).
		Save(ctx)
}

func queryBuiltinDepartment(ctx context.Context, tx *lion.Tx, code string) (*lion.Departments, error) {
	rootDept, err := tx.Departments.Query().
		Where(
			departments.CodeEQ(seedDepartmentCode(adminv1.DepartmentCode_DEPARTMENT_CODE_ROOT)),
			departments.ParentIDEQ(0),
		).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	builtinDept, err := tx.Departments.Query().
		Where(
			departments.CodeEQ("builtin"),
			departments.ParentIDEQ(rootDept.ID),
		).
		Only(ctx)
	if err != nil {
		return nil, err
	}
	return tx.Departments.Query().
		Where(
			departments.CodeEQ(code),
			departments.ParentIDEQ(builtinDept.ID),
		).
		Only(ctx)
}

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
							SortOrder:   adminMenuSortPersonal,
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
							SortOrder:   adminMenuSortSettings,
							Children: []builtinMenuSeed{
								{
									Code:        "admin.setting.auth",
									DisplayName: "身份认证",
									RoutePath:   "/setting/auth",
									SortOrder:   adminSettingsMenuSortAuth,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.auth.providers", DisplayName: "认证提供方", RoutePath: "/setting/auth/providers", SortOrder: 100},
										{Code: "admin.setting.auth.oauth2-clients", DisplayName: "OAuth2 客户端", RoutePath: "/setting/auth/oauth2-clients", SortOrder: 200},
										{Code: "admin.setting.auth.credentials", DisplayName: "凭证与令牌", RoutePath: "/setting/auth/credentials", SortOrder: 300},
									},
								},
								{
									Code:        "admin.setting.departments",
									DisplayName: "部门管理",
									RoutePath:   "/setting/departments",
									SortOrder:   adminSettingsMenuSortDepartments,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.departments.detail", DisplayName: "部门详情", RoutePath: "/setting/departments/detail", SortOrder: 100},
									},
								},
								{
									Code:        "admin.setting.menus",
									DisplayName: "菜单管理",
									RoutePath:   "/setting/menus",
									SortOrder:   adminSettingsMenuSortMenus,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.menus.list", DisplayName: "菜单列表", RoutePath: "/setting/menus/list", SortOrder: 100},
									},
								},
								{
									Code:        "admin.setting.roles",
									DisplayName: "角色管理",
									RoutePath:   "/setting/roles",
									SortOrder:   adminSettingsMenuSortRoles,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.roles.list", DisplayName: "角色列表", RoutePath: "/setting/roles/list", SortOrder: 100},
									},
								},
								{
									Code:        "admin.setting.policies",
									DisplayName: "权限策略",
									RoutePath:   "/setting/policies",
									SortOrder:   adminSettingsMenuSortPolicies,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.policies.list", DisplayName: "策略列表", RoutePath: "/setting/policies/list", SortOrder: 100},
										{Code: "admin.setting.policies.create", DisplayName: "新建策略", RoutePath: "/setting/policies/create", SortOrder: 200},
									},
								},
								{
									Code:        "admin.setting.groups",
									DisplayName: "群组管理",
									RoutePath:   "/setting/groups",
									SortOrder:   adminSettingsMenuSortGroups,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.groups.list", DisplayName: "群组列表", RoutePath: "/setting/groups/list", SortOrder: 100},
									},
								},
								{
									Code:        "admin.setting.users",
									DisplayName: "用户管理",
									RoutePath:   "/setting/users",
									SortOrder:   adminSettingsMenuSortUsers,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.users.list", DisplayName: "用户列表", RoutePath: "/setting/users/list", SortOrder: 100},
									},
								},
								{
									Code:        "admin.setting.governance",
									DisplayName: "资源治理",
									RoutePath:   "/setting/governance",
									SortOrder:   adminSettingsMenuSortGovernance,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.governance.recycle-bin", DisplayName: "回收站", RoutePath: "/setting/governance/recycle-bin", SortOrder: 100},
									},
								},
								{
									Code:        "admin.setting.config",
									DisplayName: "配置管理",
									RoutePath:   "/setting/config",
									SortOrder:   adminSettingsMenuSortConfig,
									Children: []builtinMenuSeed{
										{Code: "admin.setting.config.security", DisplayName: "认证鉴权", RoutePath: "/setting/config/security", SortOrder: 100},
										{Code: "admin.setting.config.services", DisplayName: "基础服务", RoutePath: "/setting/config/services", SortOrder: 200},
										{Code: "admin.setting.config.discover", DisplayName: "服务发现", RoutePath: "/setting/config/discover", SortOrder: 300},
										{Code: "admin.setting.config.database", DisplayName: "关系存储", RoutePath: "/setting/config/database", SortOrder: 400},
										{Code: "admin.setting.config.cachebox", DisplayName: "缓存服务", RoutePath: "/setting/config/cachebox", SortOrder: 500},
										{Code: "admin.setting.config.debugger", DisplayName: "日志调试", RoutePath: "/setting/config/debugger", SortOrder: 600},
										{Code: "admin.setting.config.objstore", DisplayName: "对象存储", RoutePath: "/setting/config/objstore", SortOrder: 700},
										{Code: "admin.setting.config.frontend", DisplayName: "前端托管", RoutePath: "/setting/config/frontend", SortOrder: 800},
										{Code: "admin.setting.config.observables", DisplayName: "遥测配置", RoutePath: "/setting/config/observables", SortOrder: 900},
										{Code: "admin.setting.config.cloudevents", DisplayName: "消息事件", RoutePath: "/setting/config/cloudevents", SortOrder: 1000},
										{Code: "admin.setting.config.automations", DisplayName: "流程编排", RoutePath: "/setting/config/automations", SortOrder: 1100},
										{Code: "admin.setting.config.aiconnector", DisplayName: "智能连接", RoutePath: "/setting/config/aiconnector", SortOrder: 1200},
										{Code: "admin.setting.config.independent", DisplayName: "独立配置", RoutePath: "/setting/config/independent", SortOrder: 1300},
									},
								},
							},
						},
						{
							Code:        "admin.devtools",
							DisplayName: "开发工具",
							RoutePath:   "/devtools",
							Icon:        "SolutionOutlined",
							SortOrder:   adminMenuSortDevtools,
							Children: []builtinMenuSeed{
								{
									Code:        "admin.devtools.api",
									DisplayName: "API 文档",
									RoutePath:   "/devtools/api",
									SortOrder:   100,
								},
								{
									Code:        "admin.devtools.mcp",
									DisplayName: "MCP 调试",
									RoutePath:   "/devtools/mcp",
									SortOrder:   200,
								},
							},
						},
						{
							Code:        "admin.observability",
							DisplayName: "可观测性",
							RoutePath:   "/observability",
							Icon:        "FundProjectionScreenOutlined",
							SortOrder:   adminMenuSortObservability,
							Children: []builtinMenuSeed{
								{
									Code:        "admin.observability.metrics",
									DisplayName: "指标监控",
									RoutePath:   "/observability/metrics",
									SortOrder:   100,
								},
								{
									Code:        "admin.observability.traces",
									DisplayName: "链路追踪",
									RoutePath:   "/observability/traces",
									SortOrder:   200,
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

// builtinMenuObsoletes 列出已下线的内置菜单 code（曾作为种子下发，现已移除）。
// 每次初始化时主动回收这些叶子菜单，保持存量库与当前种子一致，避免残留指向已下线页面的死链入口。
// 后续下线的内置菜单 code 追加到此列表即可。
var builtinMenuObsoletes = []string{
	"admin.setting.auth.tokens",     // 令牌管理已并入凭证管理（/setting/auth/credentials）
	"admin.setting.global-settings", // 全局设置已并入配置管理 > 认证鉴权（/setting/config/security）
}

// deleteObsoleteBuiltinMenus 删除已下线的内置菜单。
// 仅清理叶子节点（有子菜单时跳过，避免破坏菜单树结构）；直接按 ID 删除，绕过
// DeleteMenu RPC 对 protected 的拦截——下线受保护的内置项正是本函数的职责。
// 与 createBuiltinMenus 配套：前者补全新增种子，本函数回收废弃种子。
func deleteObsoleteBuiltinMenus(ctx context.Context, tx *lion.Tx, codes []string) error {
	for _, code := range codes {
		obj, err := tx.Menus.Query().Where(menus.CodeEQ(code)).Only(ctx)
		if lion.IsNotFound(err) {
			continue
		} else if err != nil {
			return err
		}
		hasChildren, err := tx.Menus.Query().Where(menus.ParentIDEQ(int64(obj.ID))).Exist(ctx)
		if err != nil {
			return err
		}
		if hasChildren {
			// 残留子菜单时跳过，避免误删非预期节点。
			continue
		}
		if err := tx.Menus.DeleteOneID(obj.ID).Exec(ctx); err != nil {
			return err
		}
	}
	return nil
}

// CreateDatabaseInitialize 幂等补全内置种子数据：已存在则跳过，缺失则创建。
func (a *KnownAdminAPI) CreateDatabaseInitialize(ctx context.Context, req *adminv1.CreateDatabaseInitializeRequest) (*emptypb.Empty, error) {
	result := &emptypb.Empty{}

	// password_hash 为 sha256(plaintext) 的十六进制表示（64 字符），为空时使用默认密码。
	if ph := req.GetPasswordHash(); ph != "" && len(ph) != 64 {
		return nil, errs.InvalidArgument(ctx).WithMessage("password_hash 必须是 sha256 的十六进制字符串（64 字符）").Err()
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}
	rollback := func() { _ = tx.Rollback() }
	if err := ensureGroupCapacitySetting(ctx, tx); err != nil {
		rollback()
		return nil, err
	}
	if _, err := ensureBuiltinGroup(ctx, tx, builtinGroupSeed{
		Code:        "everyone",
		DisplayName: "Everyone",
		Description: "All non-deleted users",
		UserFilter:  "status != DELETED",
		SortOrder:   10,
	}); err != nil {
		rollback()
		return nil, err
	}

	// Keep legacy SYSTEM groups protected after the protected column is added.
	// The update is intentionally idempotent and also repairs direct/manual data
	// changes before lifecycle routes are exposed.
	if _, err := tx.Groups.Update().
		Where(groups.GroupTypeEQ(int(adminv1.Group_SYSTEM))).
		SetProtected(true).
		Save(ctx); err != nil {
		rollback()
		return nil, err
	}

	superadminCode := seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN)
	superadminRole, err := tx.Roles.Query().Where(roles.CodeEQ(superadminCode)).Only(ctx)
	if lion.IsNotFound(err) {
		superadminRole, err = tx.Roles.Create().
			SetCode(superadminCode).
			SetDisplayName(superadminCode).
			SetRoleType(int(adminv1.Role_SYSTEM.Number())).
			SetRoleStatus(int(adminv1.Role_ACTIVE.Number())).
			SetProtected(true).
			SetDescription("超级管理员").
			Save(ctx)
		if err != nil {
			rollback()
			return nil, err
		}
	} else if err != nil {
		rollback()
		return nil, err
	} else {
		superadminRole, err = superadminRole.Update().
			SetRoleStatus(int(adminv1.Role_ACTIVE.Number())).
			SetProtected(true).
			Save(ctx)
		if err != nil {
			rollback()
			return nil, err
		}
	}

	adminCode := seedRoleCode(adminv1.RoleCode_ROLE_CODE_ADMIN)
	adminRole, err := ensureBuiltinRole(ctx, tx, builtinRoleSeed{
		Code:        adminCode,
		DisplayName: "普通管理员",
		Description: "系统内置普通管理员角色",
		ParentID:    superadminRole.ID,
		SortOrder:   100,
	})
	if err != nil {
		rollback()
		return nil, err
	}

	userRole, err := ensureBuiltinRole(ctx, tx, builtinRoleSeed{
		Code:        seedRoleCode(adminv1.RoleCode_ROLE_CODE_USER),
		DisplayName: "普通用户",
		Description: "系统内置普通用户角色",
		ParentID:    adminRole.ID,
		SortOrder:   200,
	})
	if err != nil {
		rollback()
		return nil, err
	}

	if _, err := ensureBuiltinRole(ctx, tx, builtinRoleSeed{
		Code:        seedRoleCode(adminv1.RoleCode_ROLE_CODE_GUEST),
		DisplayName: "访客用户",
		Description: "系统内置访客用户角色",
		ParentID:    userRole.ID,
		SortOrder:   300,
	}); err != nil {
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
		Where(rolepolicies.RoleIDEQ(superadminRole.ID), rolepolicies.PolicyIDEQ(superadminPolicy.ID)).
		Exist(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	if !rolePolicyExists {
		if err := tx.RolePolicies.Create().
			SetRoleID(superadminRole.ID).
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
			principalroles.RoleIDEQ(superadminRole.ID),
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
			SetRoleID(superadminRole.ID).
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
		passwordHash := req.GetPasswordHash()
		if passwordHash == "" {
			passwordHash = crypto.SHA256([]byte(defaultAdminPassword))
		}
		if err := tx.UserIdentities.Create().
			SetProviderID(localProvider.ID).
			SetProviderUserID(strconv.Itoa(adminUser.ID)).
			SetUserID(adminUser.ID).
			SetPasswordHash(crypto.BcryptHashMust(passwordHash)).
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

	adminDeptRoleBinding, err := tx.PrincipalRoles.Query().
		Where(
			principalroles.PrincipalTypeEQ(principalTypeDepartment),
			principalroles.PrincipalIDEQ(adminDept.ID),
			principalroles.RoleIDEQ(adminRole.ID),
		).
		Only(ctx)
	if lion.IsNotFound(err) {
		if err := tx.PrincipalRoles.Create().
			SetPrincipalType(principalTypeDepartment).
			SetPrincipalID(adminDept.ID).
			SetRoleID(adminRole.ID).
			SetBindingStatus(bindingStatusActive).
			SetDescription("初始化绑定：管理员部门默认普通管理员角色").
			Exec(ctx); err != nil {
			rollback()
			return nil, err
		}
	} else if err != nil {
		rollback()
		return nil, err
	} else {
		if err := adminDeptRoleBinding.Update().
			SetBindingStatus(bindingStatusActive).
			ClearExpiresAt().
			SetDescription("初始化绑定：管理员部门默认普通管理员角色").
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

	unassignedCode := seedDepartmentCode(adminv1.DepartmentCode_DEPARTMENT_CODE_UNASSIGNED)
	unassignedDept, err := tx.Departments.Query().
		Where(
			departments.CodeEQ(unassignedCode),
			departments.ParentIDEQ(builtinDept.ID),
		).
		Only(ctx)
	if err != nil && !lion.IsNotFound(err) {
		rollback()
		return nil, err
	}

	legacyGuestDepts, err := tx.Departments.Query().
		Where(
			departments.CodeEQ(legacyGuestDepartmentCode),
			departments.ParentIDIn(builtinDept.ID, rootDept.ID),
		).
		All(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	if unassignedDept != nil && len(legacyGuestDepts) > 0 {
		rollback()
		return nil, errs.FailedPrecondition(ctx).
			WithMessage("both legacy guest and unassigned departments exist").Err()
	}
	if len(legacyGuestDepts) > 1 {
		rollback()
		return nil, errs.FailedPrecondition(ctx).
			WithMessage("multiple legacy guest departments exist").Err()
	}

	if unassignedDept == nil {
		if len(legacyGuestDepts) == 1 {
			unassignedDept, err = legacyGuestDepts[0].Update().
				SetParentID(builtinDept.ID).
				SetCode(unassignedCode).
				SetDisplayName("待分配部门").
				SetSortOrder(2).
				SetProtected(true).
				Save(ctx)
		} else {
			unassignedDept, err = tx.Departments.Create().
				SetParentID(builtinDept.ID).
				SetCode(unassignedCode).
				SetDisplayName("待分配部门").
				SetSortOrder(2).
				SetProtected(true).
				Save(ctx)
		}
	} else {
		unassignedDept, err = unassignedDept.Update().
			SetParentID(builtinDept.ID).
			SetDisplayName("待分配部门").
			SetSortOrder(2).
			SetProtected(true).
			Save(ctx)
	}
	if err != nil {
		rollback()
		return nil, err
	}

	credCode := seedCredentialCode(adminv1.CredentialCode_CREDENTIAL_CODE_JWT_SIGNING_V1)

	credExists, err := tx.Credentials.Query().Where(
		credentials.CodeEQ(credCode),
		credentials.CredentialTypeEQ(int(adminv1.Credential_KEY_PAIR.Number())),
		credentials.CredentialUsageEQ(int(adminv1.Credential_JWKS.Number())),
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
		// fingerprint 使用公钥 SHA-256 摘要（64 字符 hex），用于幂等去重
		fp := crypto.SHA256(publicKeyBytes)
		if err := tx.Credentials.Create().
			SetCode(credCode).
			SetProtected(true).
			SetCredentialType(int(adminv1.Credential_KEY_PAIR.Number())).
			SetCredentialAlgorithm(int(adminv1.Credential_RSA.Number())).
			SetCredentialUsage(int(adminv1.Credential_JWKS.Number())).
			SetCredentialVisibility(int(adminv1.Visibility_VISIBILITY_RESTRICTED.Number())).
			SetCredentialStatus(int(adminv1.Credential_ACTIVE.Number())).
			SetCredentialSource(int(adminv1.Credential_SYSTEM.Number())).
			SetFingerprint(fp).
			SetDisplayName("JWT Signing Key v1").
			SetPublicKey(publicKeyBytes).
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

	// 回收已下线的内置菜单（如令牌管理已并入凭证管理），保持存量库与种子一致。
	if err := deleteObsoleteBuiltinMenus(ctx, tx, builtinMenuObsoletes); err != nil {
		rollback()
		return nil, err
	}

	rootMenu, err := tx.Menus.Query().Where(menus.CodeEQ("root")).Only(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	roleMenuExists, err := tx.RoleMenus.Query().
		Where(rolemenus.RoleIDEQ(superadminRole.ID), rolemenus.MenuIDEQ(rootMenu.ID)).
		Exist(ctx)
	if err != nil {
		rollback()
		return nil, err
	}
	if !roleMenuExists {
		if err := tx.RoleMenus.Create().
			SetRoleID(superadminRole.ID).
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
