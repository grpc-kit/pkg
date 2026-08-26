package admin

import "testing"

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
		{code: "admin.devtools", name: "开发工具", route: "/devtools", sort: 300},
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
