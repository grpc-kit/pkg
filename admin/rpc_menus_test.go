package admin

import (
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

func TestFilterMenusByCode_ReturnsRequestedSubtree(t *testing.T) {
	items := []*lion.Menus{
		{ID: 1, ParentID: 0, Code: "root", SortOrder: 1},
		{ID: 2, ParentID: 1, Code: "admin", SortOrder: 100},
		{ID: 3, ParentID: 2, Code: "user", SortOrder: 100},
		{ID: 4, ParentID: 2, Code: "setting", SortOrder: 200},
		{ID: 5, ParentID: 2, Code: "apidocs", SortOrder: 300},
		{ID: 6, ParentID: 3, Code: "user.profile", SortOrder: 100},
	}

	filtered := filterMenusByCode(items, "admin")
	if len(filtered) != 5 {
		t.Fatalf("expected 5 menus in admin subtree, got %d", len(filtered))
	}
	wantCodes := []string{"admin", "user", "setting", "apidocs", "user.profile"}
	for index, want := range wantCodes {
		if got := filtered[index].Code; got != want {
			t.Fatalf("unexpected code at index %d: got %q want %q", index, got, want)
		}
	}
}
