package admin

import (
	"context"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/rpc"
)

func TestHasSuperadminMenuAccessUsesRoles(t *testing.T) {
	ctx := context.Background()
	ctx = rpc.ContextWithGroups(ctx, []string{"superadmin"})
	if hasSuperadminMenuAccess(ctx) {
		t.Fatal("groups must not grant superadmin access")
	}

	ctx = rpc.ContextWithRoles(ctx, []string{"viewer"})
	if hasSuperadminMenuAccess(ctx) {
		t.Fatal("viewer role must not grant superadmin access")
	}

	ctx = rpc.ContextWithRoles(ctx, []string{seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN)})
	if !hasSuperadminMenuAccess(ctx) {
		t.Fatal("canonical superadmin role should allow access")
	}
}
