package admin

import (
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestMenuProto_DoesNotExposeSurfaceMask(t *testing.T) {
	menuMessage := adminv1.File_known_admin_v1_admin_common_proto.Messages().ByName(protoreflect.Name("Menu"))
	if menuMessage == nil {
		t.Fatalf("Menu descriptor not found")
	}
	if field := menuMessage.Fields().ByName(protoreflect.Name("surface_mask")); field != nil {
		t.Fatalf("expected Menu proto to remove surface_mask, but field %q still exists", field.Name())
	}
}
