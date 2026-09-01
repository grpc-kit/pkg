package admin

import (
	"sort"
	"testing"
)

func findBuiltinMenuSeed(items []builtinMenuSeed, code string) *builtinMenuSeed {
	for i := range items {
		if items[i].Code == code {
			return &items[i]
		}
		if found := findBuiltinMenuSeed(items[i].Children, code); found != nil {
			return found
		}
	}
	return nil
}

func TestBuiltinMenuSeeds_Devtools(t *testing.T) {
	seeds := builtinMenuSeeds()
	checks := []struct {
		code, name, route string
		sort              int
	}{
		{code: "admin.devtools", name: "开发工具", route: "/devtools", sort: adminMenuSortDevtools},
		{code: "admin.devtools.api", name: "API 文档", route: "/devtools/api", sort: 100},
		{code: "admin.devtools.mcp", name: "MCP 调试", route: "/devtools/mcp", sort: 200},
	}
	for _, check := range checks {
		seed := findBuiltinMenuSeed(seeds, check.code)
		if seed == nil {
			t.Fatalf("menu seed %q not found", check.code)
		}
		if seed.DisplayName != check.name || seed.RoutePath != check.route || seed.SortOrder != check.sort {
			t.Errorf("menu seed %q = (%q, %q, %d), want (%q, %q, %d)", check.code, seed.DisplayName, seed.RoutePath, seed.SortOrder, check.name, check.route, check.sort)
		}
		if !seed.Protected {
			t.Errorf("menu seed %q should be protected", check.code)
		}
	}
	if old := findBuiltinMenuSeed(seeds, "admin.apidocs"); old != nil {
		t.Error("legacy admin.apidocs seed should not be registered")
	}
}

func TestBuiltinMenuSeeds_Observability(t *testing.T) {
	seeds := builtinMenuSeeds()
	checks := []struct {
		code, name, route string
		sort              int
	}{
		{code: "admin.observability", name: "可观测性", route: "/observability", sort: adminMenuSortObservability},
		{code: "admin.observability.metrics", name: "指标监控", route: "/observability/metrics", sort: 100},
		{code: "admin.observability.traces", name: "链路追踪", route: "/observability/traces", sort: 200},
		{code: "admin.setting.config.observables", name: "遥测配置", route: "/setting/config/observables", sort: 900},
	}
	for _, check := range checks {
		seed := findBuiltinMenuSeed(seeds, check.code)
		if seed == nil {
			t.Fatalf("menu seed %q not found", check.code)
		}
		if seed.DisplayName != check.name || seed.RoutePath != check.route || seed.SortOrder != check.sort {
			t.Errorf("menu seed %q = (%q, %q, %d), want (%q, %q, %d)", check.code, seed.DisplayName, seed.RoutePath, seed.SortOrder, check.name, check.route, check.sort)
		}
		if !seed.Protected {
			t.Errorf("menu seed %q should be protected", check.code)
		}
	}
	parent := findBuiltinMenuSeed(seeds, "admin.observability")
	if parent == nil || parent.Icon != "FundProjectionScreenOutlined" {
		t.Fatalf("observability icon = %q, want FundProjectionScreenOutlined", parent.Icon)
	}
}

func TestBuiltinMenuSeeds_ConfigManagement(t *testing.T) {
	seed := findBuiltinMenuSeed(builtinMenuSeeds(), "admin.setting.config")
	if seed == nil {
		t.Fatal("menu seed admin.setting.config not found")
	}
	if seed.DisplayName != "配置管理" || seed.RoutePath != "/setting/config" || seed.SortOrder != adminSettingsMenuSortConfig {
		t.Fatalf("config management menu = (%q, %q, %d), want (%q, %q, %d)", seed.DisplayName, seed.RoutePath, seed.SortOrder, "配置管理", "/setting/config", adminSettingsMenuSortConfig)
	}
}

func TestBuiltinMenuSeeds_AdminSettingsOrder(t *testing.T) {
	settings := findBuiltinMenuSeed(builtinMenuSeeds(), "admin.setting")
	if settings == nil {
		t.Fatal("menu seed admin.setting not found")
	}

	items := append([]builtinMenuSeed(nil), settings.Children...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].SortOrder == items[j].SortOrder {
			return items[i].Code < items[j].Code
		}
		return items[i].SortOrder < items[j].SortOrder
	})
	want := []struct {
		code string
		sort int
	}{
		{code: "admin.setting.users", sort: adminSettingsMenuSortUsers},
		{code: "admin.setting.departments", sort: adminSettingsMenuSortDepartments},
		{code: "admin.setting.groups", sort: adminSettingsMenuSortGroups},
		{code: "admin.setting.roles", sort: adminSettingsMenuSortRoles},
		{code: "admin.setting.policies", sort: adminSettingsMenuSortPolicies},
		{code: "admin.setting.auth", sort: adminSettingsMenuSortAuth},
		{code: "admin.setting.menus", sort: adminSettingsMenuSortMenus},
		{code: "admin.setting.governance", sort: adminSettingsMenuSortGovernance},
		{code: "admin.setting.config", sort: adminSettingsMenuSortConfig},
	}
	if len(items) != len(want) {
		t.Fatalf("admin settings menu count = %d, want %d", len(items), len(want))
	}
	for i := range want {
		if items[i].Code != want[i].code || items[i].SortOrder != want[i].sort {
			t.Fatalf("admin settings menu at %d = (%q, %d), want (%q, %d)", i, items[i].Code, items[i].SortOrder, want[i].code, want[i].sort)
		}
		if !items[i].Protected {
			t.Fatalf("admin settings menu %q should be protected", items[i].Code)
		}
		if i > 0 && items[i-1].SortOrder == items[i].SortOrder {
			t.Fatalf("admin settings menus %q and %q share sort order %d", items[i-1].Code, items[i].Code, items[i].SortOrder)
		}
	}
}

func TestBuiltinMenuSeeds_AdminTopLevelOrder(t *testing.T) {
	admin := findBuiltinMenuSeed(builtinMenuSeeds(), adminMenuCode)
	if admin == nil {
		t.Fatal("admin menu seed not found")
	}

	items := append([]builtinMenuSeed(nil), admin.Children...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].SortOrder == items[j].SortOrder {
			return items[i].Code < items[j].Code
		}
		return items[i].SortOrder < items[j].SortOrder
	})
	wantCodes := []string{"admin.user", "admin.observability", "admin.devtools", "admin.setting"}
	wantSortOrders := []int{
		100,
		900,
		910,
		990,
	}
	if len(items) != len(wantCodes) {
		t.Fatalf("admin top-level menu count = %d, want %d", len(items), len(wantCodes))
	}
	for i := range items {
		if items[i].Code != wantCodes[i] || items[i].SortOrder != wantSortOrders[i] {
			t.Fatalf("admin top-level menu at %d = (%q, %d), want (%q, %d)", i, items[i].Code, items[i].SortOrder, wantCodes[i], wantSortOrders[i])
		}
		if !items[i].Protected {
			t.Fatalf("admin top-level menu %q should be protected", items[i].Code)
		}
		if items[i].SortOrder >= adminMenuSortBusinessMin && items[i].SortOrder <= adminMenuSortBusinessMax {
			t.Fatalf("framework menu %q uses reserved business sort order %d", items[i].Code, items[i].SortOrder)
		}
		if i > 0 && items[i-1].SortOrder == items[i].SortOrder {
			t.Fatalf("admin top-level menus %q and %q share sort order %d", items[i-1].Code, items[i].Code, items[i].SortOrder)
		}
	}
}
