package admin

import (
	"context"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
)

func TestGetPageSizeByStructure_FlatAndUnspecified(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name     string
		size     int32
		expected int32
	}{
		{name: "unspecified_default", size: 0, expected: 20},
		{name: "flat_default", size: 0, expected: 20},
		{name: "flat_normal", size: 88, expected: 88},
		{name: "flat_max", size: 101, expected: 100},
	}

	for _, tc := range cases {
		structure := adminv1.Structure_STRUCTURE_UNSPECIFIED
		if tc.name == "flat_default" || tc.name == "flat_normal" || tc.name == "flat_max" {
			structure = adminv1.Structure_STRUCTURE_FLAT
		}
		got := GetPageSizeByStructure(ctx, tc.size, structure)
		if got != tc.expected {
			t.Fatalf("%s: expected=%d, got=%d", tc.name, tc.expected, got)
		}
	}
}

func TestGetPageSizeByStructure_Tree(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name      string
		size      int32
		structure adminv1.Structure
		expected  int32
	}{
		{
			name:      "tree_default",
			size:      0,
			structure: adminv1.Structure_STRUCTURE_TREE,
			expected:  1000,
		},
		{
			name:      "tree_normal",
			size:      4200,
			structure: adminv1.Structure_STRUCTURE_TREE,
			expected:  4200,
		},
		{
			name:      "tree_max",
			size:      6000,
			structure: adminv1.Structure_STRUCTURE_TREE,
			expected:  5000,
		},
		{
			name:      "tree_expanded_default",
			size:      0,
			structure: adminv1.Structure_STRUCTURE_TREE_EXPANDED,
			expected:  1000,
		},
		{
			name:      "tree_expanded_max",
			size:      8000,
			structure: adminv1.Structure_STRUCTURE_TREE_EXPANDED,
			expected:  5000,
		},
	}

	for _, tc := range cases {
		got := GetPageSizeByStructure(ctx, tc.size, tc.structure)
		if got != tc.expected {
			t.Fatalf("%s: expected=%d, got=%d", tc.name, tc.expected, got)
		}
	}
}
