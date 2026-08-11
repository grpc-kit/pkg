package admin

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestValidateImmutableString(t *testing.T) {
	ctx := context.Background()
	if err := validateImmutableString(ctx, "role", "code", "admin", "admin"); err != nil {
		t.Fatalf("same immutable value must be accepted: %v", err)
	}
	err := validateImmutableString(ctx, "role", "code", "admin", "operator")
	if err == nil {
		t.Fatal("changing an immutable value must fail")
	}
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got code=%s", got)
	}
}

func TestBuiltinRoleCodes(t *testing.T) {
	for _, code := range []string{"superadmin", "admin", "user", "guest"} {
		if !isBuiltinRoleCode(code) {
			t.Errorf("expected %q to be a built-in role code", code)
		}
	}
	if isBuiltinRoleCode("custom") {
		t.Fatal("custom role must not be treated as built-in")
	}
}

func TestBuiltinDepartmentCodes(t *testing.T) {
	for _, code := range []string{"root", "builtin", "admin", "unassigned"} {
		if !isBuiltinDepartmentCode(code) {
			t.Errorf("expected %q to be a built-in department code", code)
		}
	}
	if isBuiltinDepartmentCode("engineering") {
		t.Fatal("business department must not be treated as built-in")
	}
}
