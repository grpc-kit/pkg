package cfg

import (
	"context"
	"testing"

	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/rpc"
)

func TestRolesContextDoesNotFallbackToGroups(t *testing.T) {
	ctx := context.Background()
	ctx = rpc.ContextWithGroups(ctx, []string{"legacy-role"})
	roles, ok := rpc.GetRolesFromContext(ctx)
	if ok || roles != nil {
		t.Fatalf("roles unexpectedly fell back to groups: %v, %v", roles, ok)
	}

	ctx = rpc.ContextWithRoles(ctx, []string{"canonical-role"})
	roles, ok = rpc.GetRolesFromContext(ctx)
	if !ok || len(roles) != 1 || roles[0] != "canonical-role" {
		t.Fatalf("canonical roles = %v, %v", roles, ok)
	}
}

func TestEffectiveRolesAreStoredSeparatelyFromGroups(t *testing.T) {
	security := &SecurityConfig{}
	legacy := auth.AccessTokenClaims{CommonClaims: auth.CommonClaims{
		Groups: []string{"legacy-role"},
	}}
	ctx := security.withGroups(context.Background(), legacy.Groups)
	roles := auth.EffectiveRoles(legacy)
	ctx = security.withRoles(ctx, roles)
	gotGroups, _ := rpc.GetGroupsFromContext(ctx)
	gotRoles, _ := rpc.GetRolesFromContext(ctx)
	if gotGroups[0] != "legacy-role" || len(gotRoles) != 0 {
		t.Fatalf("groups=%v roles=%v", gotGroups, gotRoles)
	}

	newClaims := auth.AccessTokenClaims{CommonClaims: auth.CommonClaims{
		Groups: []string{"legacy-role"},
		Roles:  []string{"canonical-role"},
	}}
	roles = auth.EffectiveRoles(newClaims)
	ctx = security.withRoles(ctx, roles)
	if len(roles) != 1 || roles[0] != "canonical-role" {
		t.Fatalf("roles=%v", roles)
	}
}
