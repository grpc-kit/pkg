package admin

import (
	"context"
	"reflect"
	"testing"

	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestRequiredGroupUpdatePaths(t *testing.T) {
	ctx := context.Background()
	for _, mask := range []*fieldmaskpb.FieldMask{nil, {}, {Paths: []string{" "}}} {
		if _, err := requiredGroupUpdatePaths(ctx, mask); err == nil {
			t.Fatalf("requiredGroupUpdatePaths(%v) succeeded, want error", mask)
		}
	}

	got, err := requiredGroupUpdatePaths(ctx, &fieldmaskpb.FieldMask{
		Paths: []string{"display_name", " max_members ", "display_name"},
	})
	if err != nil {
		t.Fatalf("requiredGroupUpdatePaths: %v", err)
	}
	want := []string{"display_name", "max_members"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %v, want %v", got, want)
	}
}
