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
	if !hasSuperadminMenuAccess(ctx) {
		t.Fatal("legacy groups fallback should allow superadmin")
	}

	ctx = rpc.ContextWithRoles(ctx, []string{"viewer"})
	if hasSuperadminMenuAccess(ctx) {
		t.Fatal("canonical roles must override legacy groups")
	}

	ctx = rpc.ContextWithRoles(ctx, []string{seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN)})
	if !hasSuperadminMenuAccess(ctx) {
		t.Fatal("canonical superadmin role should allow access")
	}
}
