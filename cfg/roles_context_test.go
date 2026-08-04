package cfg

import (
	"context"
	"testing"

	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/rpc"
)

func TestRolesContextAndLegacyGroupsFallback(t *testing.T) {
	ctx := context.Background()
	ctx = rpc.ContextWithGroups(ctx, []string{"legacy-role"})
	roles, ok := rpc.GetRolesFromContext(ctx)
	if !ok || len(roles) != 1 || roles[0] != "legacy-role" {
		t.Fatalf("legacy fallback = %v, %v", roles, ok)
	}

	ctx = rpc.ContextWithRoles(ctx, []string{"canonical-role"})
	roles, ok = rpc.GetRolesFromContext(ctx)
	if !ok || len(roles) != 1 || roles[0] != "canonical-role" {
		t.Fatalf("canonical roles = %v, %v", roles, ok)
	}
}

func TestEffectiveRolesAreStoredSeparatelyFromLegacyGroups(t *testing.T) {
	security := &SecurityConfig{}
	legacy := auth.AccessTokenClaims{CommonClaims: auth.CommonClaims{
		Groups: []string{"legacy-role"},
	}}
	ctx := security.withGroups(context.Background(), legacy.Groups)
	roles, source := auth.EffectiveRoles(legacy)
	ctx = security.withRoles(ctx, roles)
	if source != auth.RoleClaimSourceLegacyGroups {
		t.Fatalf("source = %q, want %q", source, auth.RoleClaimSourceLegacyGroups)
	}
	gotGroups, _ := rpc.GetGroupsFromContext(ctx)
	gotRoles, _ := rpc.GetRolesFromContext(ctx)
	if gotGroups[0] != "legacy-role" || gotRoles[0] != "legacy-role" {
		t.Fatalf("groups=%v roles=%v", gotGroups, gotRoles)
	}

	newClaims := auth.AccessTokenClaims{CommonClaims: auth.CommonClaims{
		Groups: []string{"legacy-role"},
		Roles:  []string{"canonical-role"},
	}}
	roles, source = auth.EffectiveRoles(newClaims)
	ctx = security.withRoles(ctx, roles)
	if source != auth.RoleClaimSourceRoles || roles[0] != "canonical-role" {
		t.Fatalf("source=%q roles=%v", source, roles)
	}
}
