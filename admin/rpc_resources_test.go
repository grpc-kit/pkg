package admin

import (
	"reflect"
	"testing"
)

func TestMergeUniqueInts(t *testing.T) {
	cases := []struct {
		name string
		a, b []int
		want []int
	}{
		{name: "both_empty", a: nil, b: nil, want: []int{}},
		{name: "dedupe_within_a", a: []int{1, 1, 2}, b: nil, want: []int{1, 2}},
		{name: "dedupe_across", a: []int{1, 2}, b: []int{2, 3}, want: []int{1, 2, 3}},
		{name: "order_a_then_b", a: []int{3}, b: []int{1, 2}, want: []int{3, 1, 2}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergeUniqueInts(tc.a, tc.b)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("mergeUniqueInts(%v, %v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}
