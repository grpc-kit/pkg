// DB 策略加载器（Phase 1 / P7）
//
// 从持久层（Phase 1 落地为 `pkg/lion` ent 表 lion_policies / lion_roles /
// lion_role_policies / lion_principal_roles）聚合出 OPA data JSON：
//
//	{
//	  "policies": { "<policy_code>": { "code": "...", "statements": [...] } },
//	  "roles":    { "<role_code>":   { "parent": "<parent_code>", "policies": ["<policy_code>", ...] } },
//	  "subjects": {
//	     "users":       { "<principal_id>": ["<role_code>", ...] },
//	     "groups":      { "<principal_id>": ["<role_code>", ...] },
//	     "departments": { "<principal_id>": ["<role_code>", ...] }
//	  }
//	}
//
// 字段语义、ID → string 规则、EFFECT_UNSPECIFIED 处理、过期绑定剔除等均与
// [adm/docs/roadmap/permission-opa-policy-loader.md] §3.1 一致。
//
// 设计要点：
//
//   - **解耦持久层**：Loader 不直接 import `pkg/lion`，而是通过 [PolicySource]
//     接口拉取四张表。这样 `pkg/auth` 不引入 ent / sqlite / DB 驱动等依赖，
//     单元测试用纯内存 fake 即可（无须 enttest）。
//   - **本期 P7 不挂载**：Load 输出独立 JSON，可直接 `unmarshal → inmem.NewFromObject`
//     验证；接入 `Config.DataProvider` 留给 P8。
//   - **resources / conditions 原样落盘**：Phase 1 Rego 不消费这两个字段，但 DB 中
//     的 `[]*adminv1.PolicyStatement` JSON 原样透传给 OPA data，Phase 2 启用时零迁移。
//   - **合并 static dict 不在本期**：spec 中 "合并 static dict 输出" 指 P8 在
//     `initOPARego` 里把 DB JSON 与 `StaticDict.BuildOPAData()` 同时注入 OPA data 树，
//     Loader 本身只产出 DB 三段（policies / roles / subjects）。
//
// 详见 [adm/docs/roadmap/permission-opa-policy-loader.md] §3.1 与 §6.2-P7。

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
)

// PolicySource 描述 Loader 拉取四张原始表所需的最小能力。
//
// Phase 1 由 `pkg/cfg` 在 P8 中提供 `*lion.Client` 适配实现；
// 单元测试用本包内 fake 实现即可。
//
// 实现方应**只返回未删除的数据**（软删除字段由实现侧过滤）；状态字段（policy_status
// / role_status / binding_status）的语义由 Loader 决策：
//   - 仅保留 status == 1（启用 / 生效）的行；
//   - 其他状态（含 0 = 未指定、2 = 禁用）一律剔除。
type PolicySource interface {
	// ListPolicies 返回所有 lion_policies 行。
	ListPolicies(ctx context.Context) ([]PolicyRow, error)
	// ListRoles 返回所有 lion_roles 行。
	ListRoles(ctx context.Context) ([]RoleRow, error)
	// ListRolePolicies 返回 lion_role_policies 关联。
	ListRolePolicies(ctx context.Context) ([]RolePolicyRow, error)
	// ListPrincipalRoles 返回 lion_principal_roles 绑定。
	ListPrincipalRoles(ctx context.Context) ([]PrincipalRoleRow, error)
}

// PolicyRow 对应 lion_policies 一行。
type PolicyRow struct {
	ID         int64
	Code       string
	Status     int                        // 1=启用 / 2=禁用
	Statements []*adminv1.PolicyStatement // 原样落盘，resources / conditions 字段透传
}

// RoleRow 对应 lion_roles 一行。
type RoleRow struct {
	ID       int64
	Code     string
	ParentID int64 // 0 表示无父角色
	Status   int   // 1=启用 / 2=禁用
}

// RolePolicyRow 对应 lion_role_policies 一行。
type RolePolicyRow struct {
	RoleID   int64
	PolicyID int64
}

// 主体类型常量（与 schema/principal_roles.go 的 `principal_type` 字段对齐）。
const (
	PrincipalTypeUnspecified = 0
	PrincipalTypeUser        = 1
	PrincipalTypeGroup       = 2
	PrincipalTypeDepartment  = 3
)

// PrincipalRoleRow 对应 lion_principal_roles 一行。
type PrincipalRoleRow struct {
	PrincipalType int // 1=用户 / 2=群组 / 3=部门
	PrincipalID   int64
	RoleID        int64
	BindingStatus int       // 1=生效 / 2=禁用
	ExpiredAt     time.Time // 零值表示永久有效
}

// DBLoader 把 [PolicySource] 聚合成 OPA data JSON。
//
// 零值不可用；通过 [NewDBLoader] 构造。
type DBLoader struct {
	src PolicySource
	// now 用于过滤过期绑定，便于单元测试注入时间；nil 时使用 time.Now。
	now func() time.Time
}

// NewDBLoader 构造 DBLoader。
func NewDBLoader(src PolicySource) *DBLoader {
	return &DBLoader{src: src}
}

// withClock 仅供单元测试注入虚拟时间。
func (l *DBLoader) withClock(now func() time.Time) *DBLoader {
	l.now = now
	return l
}

// Load 拉取四张表并聚合成 OPA data JSON。
//
// 输出顶层固定为三个键：policies / roles / subjects；当对应表为空时仍返回空对象 {}，
// 避免 Rego `data.<pkg>.policies[code]` 出现 undefined。
func (l *DBLoader) Load(ctx context.Context) ([]byte, error) {
	if l == nil || l.src == nil {
		return nil, fmt.Errorf("auth: DBLoader requires a non-nil PolicySource")
	}

	policies, err := l.src.ListPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: list policies: %w", err)
	}
	roles, err := l.src.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: list roles: %w", err)
	}
	rolePolicies, err := l.src.ListRolePolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: list role_policies: %w", err)
	}
	principalRoles, err := l.src.ListPrincipalRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: list principal_roles: %w", err)
	}

	now := time.Now()
	if l.now != nil {
		now = l.now()
	}

	policyByID, policiesOut := buildPoliciesSection(policies)
	rolesByID, rolesOut := buildRolesSection(roles, rolePolicies, policyByID)
	subjectsOut := buildSubjectsSection(principalRoles, rolesByID, now)

	out := struct {
		Policies map[string]policyEntry         `json:"policies"`
		Roles    map[string]roleEntry           `json:"roles"`
		Subjects map[string]map[string][]string `json:"subjects"`
	}{
		Policies: policiesOut,
		Roles:    rolesOut,
		Subjects: subjectsOut,
	}

	// 使用 protojson 已经编码 PolicyStatement 太重；这里 statements 在 buildPoliciesSection
	// 内已转成 []json.RawMessage，外层用标准 encoding/json 直接 Marshal 即可。
	buf, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("auth: marshal opa data: %w", err)
	}
	return buf, nil
}

// policyEntry 对应输出 JSON 的 policies.<code> 节点。
type policyEntry struct {
	Code       string            `json:"code"`
	Statements []json.RawMessage `json:"statements"`
}

// roleEntry 对应输出 JSON 的 roles.<code> 节点。
type roleEntry struct {
	// Parent 为空字符串表示无父角色（顶层角色）。
	Parent string `json:"parent"`
	// Policies 是按 code 字典序排序的绑定 policy code 列表；
	// 空切片序列化为 [] 而非 null（强制非 nil）。
	Policies []string `json:"policies"`
}

// buildPoliciesSection 把 PolicyRow 列表转成 policies map，同时返回 id → code 映射。
//
// 仅保留 status == 1（启用）的策略；statements 中每条用 protojson 编码以保留
// PolicyStatement.Effect 的 string enum 形态（EFFECT_UNSPECIFIED → "ALLOW" 兜底）。
func buildPoliciesSection(rows []PolicyRow) (map[int64]string, map[string]policyEntry) {
	policyByID := make(map[int64]string, len(rows))
	out := make(map[string]policyEntry, len(rows))
	for _, p := range rows {
		if p.Status != 1 {
			continue
		}
		if p.Code == "" {
			// 缺 code 的策略无法被 role 引用，跳过但仍记入 id 映射避免悬挂引用
			continue
		}
		stmts := make([]json.RawMessage, 0, len(p.Statements))
		for _, s := range p.Statements {
			if s == nil {
				continue
			}
			stmts = append(stmts, marshalStatement(s))
		}
		out[p.Code] = policyEntry{Code: p.Code, Statements: stmts}
		policyByID[p.ID] = p.Code
	}
	return policyByID, out
}

// marshalStatement 把单条 PolicyStatement 序列化为 JSON。
//
// 行为：
//   - Effect = EFFECT_UNSPECIFIED → 视作 "ALLOW"（与 spec §3.1 约定一致，避免 Rego 端
//     需要兜底未指定 effect 的语义；后续如需 fail-closed 由 admin 校验层拦截）；
//   - Actions / Resources nil → 序列化为 []，避免 Rego undefined；
//   - Conditions 透传，Phase 1 不消费但 Phase 2 直接可用。
func marshalStatement(s *adminv1.PolicyStatement) json.RawMessage {
	effect := "ALLOW"
	switch s.GetEffect() {
	case adminv1.PolicyStatement_DENY:
		effect = "DENY"
	case adminv1.PolicyStatement_ALLOW, adminv1.PolicyStatement_EFFECT_UNSPECIFIED:
		effect = "ALLOW"
	}
	actions := s.GetActions()
	if actions == nil {
		actions = []string{}
	}
	resources := s.GetResources()
	if resources == nil {
		resources = []string{}
	}
	conds := make([]map[string]interface{}, 0, len(s.GetConditions()))
	for _, c := range s.GetConditions() {
		if c == nil {
			continue
		}
		values := c.GetValues()
		if values == nil {
			values = []string{}
		}
		conds = append(conds, map[string]interface{}{
			"key":      c.GetKey(),
			"operator": c.GetOperator(),
			"values":   values,
		})
	}
	payload := map[string]interface{}{
		"effect":     effect,
		"actions":    actions,
		"resources":  resources,
		"conditions": conds,
	}
	// 内层 map 不会失败，忽略 error。
	b, _ := json.Marshal(payload)
	return b
}

// buildRolesSection 把 RoleRow + RolePolicyRow 转成 roles map，同时返回 id → code 映射。
//
// 仅保留 status == 1（启用）的角色；引用了无效（禁用 / 不存在）policy 的绑定静默丢弃。
// policies 列表按 code 字典序去重排序，保证输出确定性（便于 hash 比较 / 测试断言）。
func buildRolesSection(roles []RoleRow, rolePolicies []RolePolicyRow, policyByID map[int64]string) (map[int64]string, map[string]roleEntry) {
	roleByID := make(map[int64]string, len(roles))
	type roleScratch struct {
		parent      string
		parentRefID int64
		policies    map[string]struct{}
	}
	scratch := make(map[string]*roleScratch, len(roles))
	parentLookup := make(map[int64]string, len(roles))

	for _, r := range roles {
		if r.Status != 1 {
			continue
		}
		if r.Code == "" {
			continue
		}
		scratch[r.Code] = &roleScratch{parentRefID: r.ParentID, policies: map[string]struct{}{}}
		roleByID[r.ID] = r.Code
		parentLookup[r.ID] = r.Code
	}
	// 第二遍：把 parent_id 解析成 parent_code（父角色被禁用 / 不存在时回落为 ""）。
	for code, sc := range scratch {
		if sc.parentRefID == 0 {
			continue
		}
		if pc, ok := parentLookup[sc.parentRefID]; ok {
			sc.parent = pc
		}
		_ = code
	}

	for _, rp := range rolePolicies {
		roleCode, ok := roleByID[rp.RoleID]
		if !ok {
			continue
		}
		policyCode, ok := policyByID[rp.PolicyID]
		if !ok {
			continue
		}
		scratch[roleCode].policies[policyCode] = struct{}{}
	}

	out := make(map[string]roleEntry, len(scratch))
	for code, sc := range scratch {
		codes := make([]string, 0, len(sc.policies))
		for c := range sc.policies {
			codes = append(codes, c)
		}
		sort.Strings(codes)
		out[code] = roleEntry{Parent: sc.parent, Policies: codes}
	}
	return roleByID, out
}

// buildSubjectsSection 把 PrincipalRoleRow 转成 subjects 三个子表
// （users / groups / departments，分别对应 principal_type 1 / 2 / 3）。
//
// 过滤规则：
//   - binding_status != 1 剔除；
//   - 角色不存在或被禁用（不在 rolesByID 中）剔除；
//   - principal_id <= 0 剔除（schema 约束 Positive，但运行时数据兜底）；
//   - expired_at 非零且早于 now 剔除；
//   - 每个 principal 的角色列表按 code 字典序去重排序，保证输出确定性。
func buildSubjectsSection(rows []PrincipalRoleRow, rolesByID map[int64]string, now time.Time) map[string]map[string][]string {
	users := map[string]map[string]struct{}{}
	groups := map[string]map[string]struct{}{}
	departments := map[string]map[string]struct{}{}

	for _, b := range rows {
		if b.BindingStatus != 1 {
			continue
		}
		if b.PrincipalID <= 0 {
			continue
		}
		if !b.ExpiredAt.IsZero() && !b.ExpiredAt.After(now) {
			continue
		}
		roleCode, ok := rolesByID[b.RoleID]
		if !ok {
			continue
		}
		var bucket map[string]map[string]struct{}
		switch b.PrincipalType {
		case PrincipalTypeUser:
			bucket = users
		case PrincipalTypeGroup:
			bucket = groups
		case PrincipalTypeDepartment:
			bucket = departments
		default:
			continue
		}
		pid := strconv.FormatInt(b.PrincipalID, 10)
		if bucket[pid] == nil {
			bucket[pid] = map[string]struct{}{}
		}
		bucket[pid][roleCode] = struct{}{}
	}

	return map[string]map[string][]string{
		"users":       collapseRoleSet(users),
		"groups":      collapseRoleSet(groups),
		"departments": collapseRoleSet(departments),
	}
}

// collapseRoleSet 把 principal_id → set<role_code> 折叠成 principal_id → 排序后 []role_code。
// 空入参返回非 nil 空 map，保证 JSON 输出为 {} 而非 null。
func collapseRoleSet(in map[string]map[string]struct{}) map[string][]string {
	out := make(map[string][]string, len(in))
	for pid, set := range in {
		codes := make([]string, 0, len(set))
		for c := range set {
			codes = append(codes, c)
		}
		sort.Strings(codes)
		out[pid] = codes
	}
	return out
}
