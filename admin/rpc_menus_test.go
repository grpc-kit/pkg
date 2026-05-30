package admin

import (
	"testing"

	"github.com/grpc-kit/pkg/lion"
)

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
