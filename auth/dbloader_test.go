package auth

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"testing"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
)

// fakePolicySource 提供可控的内存实现，避免在 pkg/auth 单测中引入 sqlite / ent 依赖。
type fakePolicySource struct {
	policies       []PolicyRow
	roles          []RoleRow
	rolePolicies   []RolePolicyRow
	principalRoles []PrincipalRoleRow

	errPolicies       error
	errRoles          error
	errRolePolicies   error
	errPrincipalRoles error
}

func (f *fakePolicySource) ListPolicies(_ context.Context) ([]PolicyRow, error) {
	return f.policies, f.errPolicies
}
func (f *fakePolicySource) ListRoles(_ context.Context) ([]RoleRow, error) {
	return f.roles, f.errRoles
}
func (f *fakePolicySource) ListRolePolicies(_ context.Context) ([]RolePolicyRow, error) {
	return f.rolePolicies, f.errRolePolicies
}
func (f *fakePolicySource) ListPrincipalRoles(_ context.Context) ([]PrincipalRoleRow, error) {
	return f.principalRoles, f.errPrincipalRoles
}

// loadDecoded 解码 Load 输出为 generic map，便于断言。
func loadDecoded(t *testing.T, l *DBLoader) map[string]interface{} {
	t.Helper()
	raw, err := l.Load(context.Background())
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Load output is not valid JSON: %v\nraw=%s", err, string(raw))
	}
	return out
}

// TestDBLoader_NilSource 验证 nil 防御。
func TestDBLoader_NilSource(t *testing.T) {
	if _, err := (&DBLoader{}).Load(context.Background()); err == nil {
		t.Fatal("expected error when PolicySource is nil")
	}
	var l *DBLoader
	if _, err := l.Load(context.Background()); err == nil {
		t.Fatal("expected error when DBLoader receiver is nil")
	}
}

// TestDBLoader_TopLevelKeysAlwaysPresent 即使全部表为空，三段键必须存在且为 {}，
// 避免 Rego `data.<pkg>.policies[code]` 触发 undefined。
func TestDBLoader_TopLevelKeysAlwaysPresent(t *testing.T) {
	l := NewDBLoader(&fakePolicySource{})
	out := loadDecoded(t, l)
	for _, key := range []string{"policies", "roles", "subjects"} {
		v, ok := out[key]
		if !ok {
			t.Fatalf("missing top-level key %q in output: %#v", key, out)
		}
		m, ok := v.(map[string]interface{})
		if !ok {
			t.Fatalf("top-level key %q is not an object: %#v", key, v)
		}
		// subjects 内还要有 users / groups / departments 三个空 map
		if key == "subjects" {
			for _, sub := range []string{"users", "groups", "departments"} {
				if _, ok := m[sub]; !ok {
					t.Fatalf("subjects missing sub-key %q: %#v", sub, m)
				}
			}
		}
	}
}

// TestDBLoader_PoliciesFiltering 验证禁用 / 空 code 策略被剔除，启用策略保留。
func TestDBLoader_PoliciesFiltering(t *testing.T) {
	src := &fakePolicySource{
		policies: []PolicyRow{
			{ID: 1, Code: "p_enabled", Status: 1, Statements: []*adminv1.PolicyStatement{
				{Effect: adminv1.PolicyStatement_ALLOW, Actions: []string{"svc:read"}},
			}},
			{ID: 2, Code: "p_disabled", Status: 2, Statements: nil},
			{ID: 3, Code: "", Status: 1, Statements: nil}, // 缺 code 跳过
			{ID: 4, Code: "p_unspecified_status", Status: 0, Statements: nil},
		},
	}
	out := loadDecoded(t, NewDBLoader(src))
	policies := out["policies"].(map[string]interface{})
	if _, ok := policies["p_enabled"]; !ok {
		t.Fatal("expected p_enabled to be present")
	}
	if _, ok := policies["p_disabled"]; ok {
		t.Fatal("disabled policy must be filtered")
	}
	if _, ok := policies[""]; ok {
		t.Fatal("policy with empty code must be filtered")
	}
	if _, ok := policies["p_unspecified_status"]; ok {
		t.Fatal("policy with status=0 must be filtered")
	}
}

// TestDBLoader_StatementEncoding 验证 statement 字段的转换：
//   - EFFECT_UNSPECIFIED → "ALLOW"
//   - DENY → "DENY"
//   - actions / resources / conditions nil → []
//   - conditions 透传
func TestDBLoader_StatementEncoding(t *testing.T) {
	src := &fakePolicySource{
		policies: []PolicyRow{
			{ID: 1, Code: "p1", Status: 1, Statements: []*adminv1.PolicyStatement{
				{Effect: adminv1.PolicyStatement_EFFECT_UNSPECIFIED, Actions: nil, Resources: nil, Conditions: nil},
				{Effect: adminv1.PolicyStatement_DENY, Actions: []string{"svc:write"}, Resources: []string{"grn:aws:s3:::bucket"},
					Conditions: []*adminv1.PolicyStatement_Condition{
						{Key: "ip", Operator: "IpAddress", Values: []string{"10.0.0.0/8"}},
					}},
				nil, // 跳过
			}},
		},
	}
	out := loadDecoded(t, NewDBLoader(src))
	stmts := out["policies"].(map[string]interface{})["p1"].(map[string]interface{})["statements"].([]interface{})
	if len(stmts) != 2 {
		t.Fatalf("expected 2 statements (nil skipped), got %d: %#v", len(stmts), stmts)
	}

	s0 := stmts[0].(map[string]interface{})
	if s0["effect"] != "ALLOW" {
		t.Errorf("EFFECT_UNSPECIFIED must map to ALLOW, got %v", s0["effect"])
	}
	if got := s0["actions"].([]interface{}); len(got) != 0 {
		t.Errorf("nil actions must serialize to [], got %#v", got)
	}
	if got := s0["resources"].([]interface{}); len(got) != 0 {
		t.Errorf("nil resources must serialize to [], got %#v", got)
	}
	if got := s0["conditions"].([]interface{}); len(got) != 0 {
		t.Errorf("nil conditions must serialize to [], got %#v", got)
	}

	s1 := stmts[1].(map[string]interface{})
	if s1["effect"] != "DENY" {
		t.Errorf("DENY effect lost: %v", s1["effect"])
	}
	conds := s1["conditions"].([]interface{})
	if len(conds) != 1 {
		t.Fatalf("expected 1 condition: %#v", conds)
	}
	c := conds[0].(map[string]interface{})
	if c["key"] != "ip" || c["operator"] != "IpAddress" {
		t.Errorf("condition key/operator transformed: %#v", c)
	}
}

// TestDBLoader_RolesAggregation 验证 role 聚合：
//   - 禁用 role / 空 code role 剔除
//   - 父角色解析
//   - 父角色禁用 → parent 回落为 ""
//   - 引用禁用 / 不存在 policy 的 role_policies 行静默丢弃
//   - policies 列表字典序去重
func TestDBLoader_RolesAggregation(t *testing.T) {
	src := &fakePolicySource{
		policies: []PolicyRow{
			{ID: 10, Code: "p_a", Status: 1},
			{ID: 11, Code: "p_b", Status: 1},
			{ID: 12, Code: "p_disabled", Status: 2},
		},
		roles: []RoleRow{
			{ID: 1, Code: "r_root", ParentID: 0, Status: 1},
			{ID: 2, Code: "r_child", ParentID: 1, Status: 1},
			{ID: 3, Code: "r_orphan_parent", ParentID: 99, Status: 1}, // 父不存在
			{ID: 4, Code: "r_parent_disabled", ParentID: 5, Status: 1},
			{ID: 5, Code: "r_disabled", ParentID: 0, Status: 2},
			{ID: 6, Code: "", ParentID: 0, Status: 1}, // 空 code
		},
		rolePolicies: []RolePolicyRow{
			{RoleID: 2, PolicyID: 11},  // r_child → p_b
			{RoleID: 2, PolicyID: 10},  // r_child → p_a
			{RoleID: 2, PolicyID: 10},  // duplicate
			{RoleID: 2, PolicyID: 12},  // 引用禁用 policy → 丢弃
			{RoleID: 2, PolicyID: 999}, // 引用不存在 policy → 丢弃
			{RoleID: 99, PolicyID: 10}, // 引用不存在 role → 丢弃
		},
	}
	out := loadDecoded(t, NewDBLoader(src))
	roles := out["roles"].(map[string]interface{})

	if _, ok := roles["r_disabled"]; ok {
		t.Error("disabled role must be filtered")
	}
	if _, ok := roles[""]; ok {
		t.Error("role with empty code must be filtered")
	}

	rChild := roles["r_child"].(map[string]interface{})
	if rChild["parent"] != "r_root" {
		t.Errorf("r_child parent expected r_root, got %v", rChild["parent"])
	}
	gotPolicies := rChild["policies"].([]interface{})
	wantPolicies := []string{"p_a", "p_b"} // 字典序去重
	if len(gotPolicies) != len(wantPolicies) {
		t.Fatalf("r_child policies length: got %v want %v", gotPolicies, wantPolicies)
	}
	for i, want := range wantPolicies {
		if gotPolicies[i] != want {
			t.Errorf("r_child policies[%d]: got %v want %v", i, gotPolicies[i], want)
		}
	}

	if roles["r_orphan_parent"].(map[string]interface{})["parent"] != "" {
		t.Error("role with non-existent parent_id should fall back to empty parent")
	}
	if roles["r_parent_disabled"].(map[string]interface{})["parent"] != "" {
		t.Error("role with disabled parent should fall back to empty parent")
	}

	// 无 policy 的 role 必须是 [] 不能是 null
	rRoot := roles["r_root"].(map[string]interface{})
	if pols, ok := rRoot["policies"].([]interface{}); !ok || pols == nil {
		t.Errorf("r_root.policies must be non-null array, got %#v", rRoot["policies"])
	}
}

// TestDBLoader_SubjectsAggregation 验证：
//   - 三类主体分别落到 users / groups / departments
//   - 未指定类型 / 非法 principal_id 剔除
//   - binding_status != 1 剔除
//   - 角色不存在 / 禁用 剔除
//   - expired_at 在 now 之前 剔除；之后保留；零值保留（永久）
//   - 同一 principal 多角色去重 + 字典序排序
//   - principal_id 序列化为字符串
func TestDBLoader_SubjectsAggregation(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	src := &fakePolicySource{
		policies: []PolicyRow{{ID: 1, Code: "p1", Status: 1}},
		roles: []RoleRow{
			{ID: 100, Code: "r_a", Status: 1},
			{ID: 101, Code: "r_b", Status: 1},
			{ID: 102, Code: "r_disabled", Status: 2},
		},
		principalRoles: []PrincipalRoleRow{
			{PrincipalType: PrincipalTypeUser, PrincipalID: 1, RoleID: 100, BindingStatus: 1},
			{PrincipalType: PrincipalTypeUser, PrincipalID: 1, RoleID: 101, BindingStatus: 1},
			{PrincipalType: PrincipalTypeUser, PrincipalID: 1, RoleID: 100, BindingStatus: 1}, // dup
			{PrincipalType: PrincipalTypeUser, PrincipalID: 1, RoleID: 102, BindingStatus: 1}, // role 禁用
			{PrincipalType: PrincipalTypeUser, PrincipalID: 1, RoleID: 999, BindingStatus: 1}, // role 不存在
			{PrincipalType: PrincipalTypeUser, PrincipalID: 2, RoleID: 100, BindingStatus: 2}, // binding 禁用
			{PrincipalType: PrincipalTypeUser, PrincipalID: 3, RoleID: 100, BindingStatus: 1,
				ExpiredAt: now.Add(-time.Hour)}, // 已过期
			{PrincipalType: PrincipalTypeUser, PrincipalID: 4, RoleID: 100, BindingStatus: 1,
				ExpiredAt: now.Add(time.Hour)}, // 未过期
			{PrincipalType: PrincipalTypeUser, PrincipalID: 5, RoleID: 100, BindingStatus: 1}, // 永久
			{PrincipalType: PrincipalTypeUser, PrincipalID: 0, RoleID: 100, BindingStatus: 1}, // 非法 id
			{PrincipalType: PrincipalTypeGroup, PrincipalID: 10, RoleID: 100, BindingStatus: 1},
			{PrincipalType: PrincipalTypeDepartment, PrincipalID: 20, RoleID: 101, BindingStatus: 1},
			{PrincipalType: PrincipalTypeUnspecified, PrincipalID: 1, RoleID: 100, BindingStatus: 1}, // 未指定类型
		},
	}
	l := NewDBLoader(src).withClock(func() time.Time { return now })
	out := loadDecoded(t, l)

	subjects := out["subjects"].(map[string]interface{})
	users := subjects["users"].(map[string]interface{})
	groups := subjects["groups"].(map[string]interface{})
	depts := subjects["departments"].(map[string]interface{})

	// users[1] 应包含 r_a + r_b 字典序去重
	u1 := toStringSlice(t, users["1"])
	if !equalSorted(u1, []string{"r_a", "r_b"}) {
		t.Errorf("users[1] expected [r_a r_b], got %v", u1)
	}
	if _, ok := users["2"]; ok {
		t.Error("user 2 binding disabled should be filtered")
	}
	if _, ok := users["3"]; ok {
		t.Error("user 3 expired should be filtered")
	}
	u4 := toStringSlice(t, users["4"])
	if !equalSorted(u4, []string{"r_a"}) {
		t.Errorf("users[4] expected [r_a], got %v", u4)
	}
	u5 := toStringSlice(t, users["5"])
	if !equalSorted(u5, []string{"r_a"}) {
		t.Errorf("users[5] expected [r_a], got %v", u5)
	}
	if _, ok := users["0"]; ok {
		t.Error("user with id=0 must be filtered")
	}

	if g10 := toStringSlice(t, groups["10"]); !equalSorted(g10, []string{"r_a"}) {
		t.Errorf("groups[10] expected [r_a], got %v", g10)
	}
	if d20 := toStringSlice(t, depts["20"]); !equalSorted(d20, []string{"r_b"}) {
		t.Errorf("departments[20] expected [r_b], got %v", d20)
	}
}

// TestDBLoader_SourceErrorsPropagate 任一 List 报错都需要带 wrap 信息返回。
func TestDBLoader_SourceErrorsPropagate(t *testing.T) {
	baseErr := errors.New("db boom")
	cases := []struct {
		name   string
		mutate func(*fakePolicySource)
	}{
		{"policies", func(f *fakePolicySource) { f.errPolicies = baseErr }},
		{"roles", func(f *fakePolicySource) { f.errRoles = baseErr }},
		{"role_policies", func(f *fakePolicySource) { f.errRolePolicies = baseErr }},
		{"principal_roles", func(f *fakePolicySource) { f.errPrincipalRoles = baseErr }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := &fakePolicySource{}
			tc.mutate(src)
			_, err := NewDBLoader(src).Load(context.Background())
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, baseErr) {
				t.Errorf("error chain should preserve baseErr, got %v", err)
			}
		})
	}
}

// TestDBLoader_DeterministicOutput 同一输入两次调用应产生**字节相同**的 JSON，
// 便于 Reload 期（P9）做指纹/版本对比。
func TestDBLoader_DeterministicOutput(t *testing.T) {
	src := &fakePolicySource{
		policies: []PolicyRow{
			{ID: 1, Code: "p_a", Status: 1},
			{ID: 2, Code: "p_b", Status: 1},
		},
		roles: []RoleRow{
			{ID: 10, Code: "r_x", Status: 1},
		},
		rolePolicies: []RolePolicyRow{
			{RoleID: 10, PolicyID: 2},
			{RoleID: 10, PolicyID: 1},
		},
		principalRoles: []PrincipalRoleRow{
			{PrincipalType: PrincipalTypeUser, PrincipalID: 7, RoleID: 10, BindingStatus: 1},
			{PrincipalType: PrincipalTypeUser, PrincipalID: 3, RoleID: 10, BindingStatus: 1},
		},
	}
	fixed := time.Unix(1700000000, 0)
	l := NewDBLoader(src).withClock(func() time.Time { return fixed })
	a, err := l.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := l.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// principal_id 在内部 map 的 key 是 string，go map 迭代不保证顺序，但我们对每个
	// principal 的 role 列表做了 sort.Strings —— 顶层 principal_id key 仍可能乱序导致
	// encoding/json Marshal 输出不稳定。这里只比较解码后的等价性。
	var ma, mb map[string]interface{}
	if err := json.Unmarshal(a, &ma); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &mb); err != nil {
		t.Fatal(err)
	}
	// 用 deep compare（通过再序列化为 sorted JSON 比较）
	if !jsonEqual(t, ma, mb) {
		t.Errorf("two Load calls produced different output:\na=%s\nb=%s", a, b)
	}
}

// equalSorted 比较两个字符串切片在排序后是否相等。
func equalSorted(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

// toStringSlice 把 []interface{} 解为 []string。
func toStringSlice(t *testing.T, v interface{}) []string {
	t.Helper()
	if v == nil {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T (%v)", v, v)
	}
	out := make([]string, len(arr))
	for i, e := range arr {
		s, ok := e.(string)
		if !ok {
			t.Fatalf("element %d is not string: %T (%v)", i, e, e)
		}
		out[i] = s
	}
	return out
}

// jsonEqual 通过 Marshal → Unmarshal round-trip 比较语义相等性（绕开 map 迭代序）。
func jsonEqual(t *testing.T, a, b interface{}) bool {
	t.Helper()
	ab, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var ax, bx interface{}
	if err := json.Unmarshal(ab, &ax); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bb, &bx); err != nil {
		t.Fatal(err)
	}
	// 重新 Marshal 第二轮（json 包对 map 输出按 key 排序），比对字节
	ay, _ := json.Marshal(ax)
	by, _ := json.Marshal(bx)
	return string(ay) == string(by)
}
