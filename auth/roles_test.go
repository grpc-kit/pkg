package auth

import "testing"

func TestEffectiveRoles(t *testing.T) {
	tests := []struct {
		name   string
		claims AccessTokenClaims
		want   []string
		source RoleClaimSource
	}{
		{
			name: "roles are authoritative",
			claims: AccessTokenClaims{CommonClaims: CommonClaims{
				Groups: []string{"legacy-admin"},
				Roles:  []string{" admin ", "admin", "viewer"},
			}},
			want:   []string{"admin", "viewer"},
			source: RoleClaimSourceRoles,
		},
		{
			name: "legacy groups fallback",
			claims: AccessTokenClaims{CommonClaims: CommonClaims{
				Groups: []string{"admin", "admin", " viewer "},
			}},
			want:   []string{"admin", "viewer"},
			source: RoleClaimSourceLegacyGroups,
		},
		{
			name: "explicit empty roles do not fallback",
			claims: AccessTokenClaims{CommonClaims: CommonClaims{
				Groups: []string{"admin"},
				Roles:  []string{},
			}},
			want:   []string{},
			source: RoleClaimSourceRoles,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, source := EffectiveRoles(tt.claims)
			if source != tt.source {
				t.Fatalf("source = %q, want %q", source, tt.source)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("roles = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("roles = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
