package admin

import (
	"strings"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
)

func TestMenuVisibilityFromProto_DefaultsToGlobal(t *testing.T) {
	if got := menuVisibilityFromProto(adminv1.Visibility_VISIBILITY_UNSPECIFIED); got != "global" {
		t.Fatalf("menuVisibilityFromProto(VISIBILITY_UNSPECIFIED) = %q, want %q", got, "global")
	}
}

func TestMenuVisibilityToProto_UnknownStringReturnsUnspecified(t *testing.T) {
	if got := menuVisibilityToProto("full"); got != adminv1.Visibility_VISIBILITY_UNSPECIFIED {
		t.Fatalf("menuVisibilityToProto(%q) = %v, want %v", "full", got, adminv1.Visibility_VISIBILITY_UNSPECIFIED)
	}
}

func TestFilterMenusByVisibility_RestrictedOnlyShowsCreatorOrSuperadmin(t *testing.T) {
	items := []*lion.Menus{
		{ID: 1, ParentID: 0, Code: "root", Visibility: "global", CreatedBy: 1},
		{ID: 2, ParentID: 1, Code: "private", Visibility: "restricted", CreatedBy: 42},
	}

	filtered := filterMenusByVisibility(items, 7, false)
	if len(filtered) != 1 || filtered[0].Code != "root" {
		t.Fatalf("expected non-creator to only see root menu, got %#v", filtered)
	}

	filtered = filterMenusByVisibility(items, 42, false)
	if len(filtered) != 2 {
		t.Fatalf("expected creator to see both menus, got %d", len(filtered))
	}

	filtered = filterMenusByVisibility(items, 7, true)
	if len(filtered) != 2 {
		t.Fatalf("expected superadmin to see both menus, got %d", len(filtered))
	}
}

func TestPruneMenusWithoutVisibleAncestors_RemovesOrphanedDescendants(t *testing.T) {
	items := []*lion.Menus{
		{ID: 1, ParentID: 0, Code: "root", Visibility: "restricted", CreatedBy: 42},
		{ID: 2, ParentID: 1, Code: "child", Visibility: "global", CreatedBy: 1},
		{ID: 3, ParentID: 2, Code: "grandchild", Visibility: "global", CreatedBy: 1},
	}

	filtered := filterMenusByVisibility(items, 7, false)
	if len(filtered) != 2 {
		t.Fatalf("expected direct non-restricted descendants to survive visibility filter before tree pruning, got %#v", filtered)
	}
	pruned := pruneMenusWithoutVisibleAncestors(filtered)
	if len(pruned) != 0 {
		t.Fatalf("expected descendants of hidden parent to be pruned, got %#v", pruned)
	}
}

func TestLionMenuToProto_ProtectedField(t *testing.T) {
	// protected=true 应正确映射到 proto
	protectedMenu := &lion.Menus{
		ID:        1,
		Code:      "root",
		Protected: true,
	}
	got := lionMenuToProto(protectedMenu)
	if !got.Protected {
		t.Fatalf("lionMenuToProto: expected Protected=true, got false")
	}

	// protected=false 应正确映射到 proto
	normalMenu := &lion.Menus{
		ID:        2,
		Code:      "custom",
		Protected: false,
	}
	got = lionMenuToProto(normalMenu)
	if got.Protected {
		t.Fatalf("lionMenuToProto: expected Protected=false, got true")
	}
}

func TestFilterMenusByCode_ReturnsRequestedSubtree(t *testing.T) {
	items := []*lion.Menus{
		{ID: 1, ParentID: 0, Code: "root", SortOrder: 1},
		{ID: 2, ParentID: 1, Code: "admin", SortOrder: 100},
		{ID: 3, ParentID: 2, Code: "admin.user", SortOrder: 100},
		{ID: 4, ParentID: 2, Code: "admin.setting", SortOrder: 200},
		{ID: 5, ParentID: 2, Code: "admin.apidocs", SortOrder: 300},
		{ID: 6, ParentID: 3, Code: "admin.user.profile", SortOrder: 100},
	}

	filtered := filterMenusByCode(items, "admin")
	if len(filtered) != 5 {
		t.Fatalf("expected 5 menus in admin subtree, got %d", len(filtered))
	}
	wantCodes := []string{"admin", "admin.user", "admin.setting", "admin.apidocs", "admin.user.profile"}
	for index, want := range wantCodes {
		if got := filtered[index].Code; got != want {
			t.Fatalf("unexpected code at index %d: got %q want %q", index, got, want)
		}
	}
}

func TestResolveMenuCode(t *testing.T) {
	tests := []struct {
		name       string
		parentCode string
		userCode   string
		wantErr    bool
		wantPrefix string // 非空时检查结果是否以此前缀开头
		wantExact  string // 非空时检查结果是否完全匹配
	}{
		{
			name:       "parent + empty user code → auto-generate with prefix",
			parentCode: "admin",
			userCode:   "",
			wantPrefix: "admin.",
		},
		{
			name:       "parent + user code without prefix → auto-prepend",
			parentCode: "admin",
			userCode:   "user",
			wantExact:  "admin.user",
		},
		{
			name:       "parent + user code already prefixed → use as-is",
			parentCode: "admin",
			userCode:   "admin.setting",
			wantExact:  "admin.setting",
		},
		{
			name:       "no parent + empty user code → 6-char random",
			parentCode: "",
			userCode:   "",
			wantErr:    false,
		},
		{
			name:       "no parent + user code → validate as-is",
			parentCode: "",
			userCode:   "portal",
			wantExact:  "portal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveMenuCode(tt.parentCode, tt.userCode)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantExact != "" && got != tt.wantExact {
				t.Fatalf("got %q, want exact %q", got, tt.wantExact)
			}
			if tt.wantPrefix != "" && !strings.HasPrefix(got, tt.wantPrefix) {
				t.Fatalf("got %q, want prefix %q", got, tt.wantPrefix)
			}
			// 自动生成的情况，检查随机部分长度
			if tt.userCode == "" && tt.parentCode != "" {
				// parentCode + "." + 6 chars
				expectedLen := len(tt.parentCode) + 1 + 6
				if len(got) != expectedLen {
					t.Fatalf("auto-generated code length = %d, want %d (parentCode + . + 6)", len(got), expectedLen)
				}
			}
			if tt.userCode == "" && tt.parentCode == "" {
				if len(got) != 6 {
					t.Fatalf("top-level auto-generated code length = %d, want 6", len(got))
				}
			}
		})
	}
}

func TestNormalizeMenuSortOrder(t *testing.T) {
	tests := []struct {
		name       string
		parentCode string
		requested  int
		want       int
		wantErr    bool
	}{
		{name: "admin default", parentCode: adminMenuCode, requested: 0, want: adminMenuSortBusinessDefault},
		{name: "admin minimum", parentCode: adminMenuCode, requested: adminMenuSortBusinessMin, want: adminMenuSortBusinessMin},
		{name: "admin middle", parentCode: adminMenuCode, requested: 500, want: 500},
		{name: "admin maximum", parentCode: adminMenuCode, requested: adminMenuSortBusinessMax, want: adminMenuSortBusinessMax},
		{name: "admin below range", parentCode: adminMenuCode, requested: adminMenuSortBusinessMin - 1, wantErr: true},
		{name: "admin above range", parentCode: adminMenuCode, requested: adminMenuSortBusinessMax + 1, wantErr: true},
		{name: "admin framework range", parentCode: adminMenuCode, requested: adminMenuSortObservability, wantErr: true},
		{name: "nested default", parentCode: "admin.setting", requested: 0, want: defaultMenuSortOrder},
		{name: "nested framework-like number", parentCode: "admin.setting", requested: 900, want: 900},
		{name: "negative", parentCode: "admin.setting", requested: -1, wantErr: true},
		{name: "above global maximum", parentCode: "admin.setting", requested: maxMenuSortOrder + 1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeMenuSortOrder(tt.parentCode, tt.requested)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizeMenuSortOrder(%q, %d) expected error, got %d", tt.parentCode, tt.requested, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeMenuSortOrder(%q, %d) unexpected error: %v", tt.parentCode, tt.requested, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeMenuSortOrder(%q, %d) = %d, want %d", tt.parentCode, tt.requested, got, tt.want)
			}
		})
	}
}

func TestBuildMenuTree_AdminBusinessMenusStayBetweenFrameworkMenus(t *testing.T) {
	items := []*lion.Menus{
		{ID: 11, ParentID: 8, Code: "admin.project.create", SortOrder: 200},
		{ID: 6, ParentID: 2, Code: "admin.setting", SortOrder: 990},
		{ID: 9, ParentID: 2, Code: "admin.order", SortOrder: 300},
		{ID: 1, ParentID: 0, Code: "root", SortOrder: 1},
		{ID: 5, ParentID: 2, Code: "admin.devtools", SortOrder: 910},
		{ID: 8, ParentID: 2, Code: "admin.project", SortOrder: 300},
		{ID: 3, ParentID: 2, Code: "admin.user", SortOrder: 100},
		{ID: 10, ParentID: 8, Code: "admin.project.list", SortOrder: 100},
		{ID: 4, ParentID: 2, Code: "admin.observability", SortOrder: 900},
		{ID: 2, ParentID: 1, Code: "admin", SortOrder: 100},
	}

	tree := buildMenuTree(items)
	if len(tree) != 1 || tree[0].Code != "root" {
		t.Fatalf("unexpected menu roots: %#v", tree)
	}
	if len(tree[0].Children) != 1 || tree[0].Children[0].Code != adminMenuCode {
		t.Fatalf("unexpected root children: %#v", tree[0].Children)
	}
	adminChildren := tree[0].Children[0].Children
	wantAdminCodes := []string{
		"admin.user",
		"admin.project",
		"admin.order",
		"admin.observability",
		"admin.devtools",
		"admin.setting",
	}
	if len(adminChildren) != len(wantAdminCodes) {
		t.Fatalf("admin child count = %d, want %d", len(adminChildren), len(wantAdminCodes))
	}
	for i, want := range wantAdminCodes {
		if got := adminChildren[i].Code; got != want {
			t.Fatalf("admin child at %d = %q, want %q", i, got, want)
		}
	}
	projectChildren := adminChildren[1].Children
	if len(projectChildren) != 2 || projectChildren[0].Code != "admin.project.list" || projectChildren[1].Code != "admin.project.create" {
		t.Fatalf("unexpected project child order: %#v", projectChildren)
	}
}
