package auth

import (
	"encoding/json"
	"testing"
)

func TestEffectiveRoles(t *testing.T) {
	tests := []struct {
		name   string
		claims AccessTokenClaims
		want   []string
	}{
		{
			name: "roles are authoritative",
			claims: AccessTokenClaims{CommonClaims: CommonClaims{
				Groups: []string{"legacy-admin"},
				Roles:  []string{" admin ", "admin", "viewer"},
			}},
			want: []string{"admin", "viewer"},
		},
		{
			name: "groups are never roles",
			claims: AccessTokenClaims{CommonClaims: CommonClaims{
				Groups: []string{"admin", "admin", " viewer "},
			}},
			want: []string{},
		},
		{
			name: "explicit empty roles do not fallback",
			claims: AccessTokenClaims{CommonClaims: CommonClaims{
				Groups: []string{"admin"},
				Roles:  []string{},
			}},
			want: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EffectiveRoles(tt.claims)
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

func TestEffectiveRolesJSONEmptyVariantsNeverFallback(t *testing.T) {
	for _, payload := range []string{
		`{"groups":["admin"]}`,
		`{"roles":null,"groups":["admin"]}`,
		`{"roles":[],"groups":["admin"]}`,
	} {
		var claims AccessTokenClaims
		if err := json.Unmarshal([]byte(payload), &claims); err != nil {
			t.Fatalf("unmarshal %s: %v", payload, err)
		}
		if roles := EffectiveRoles(claims); len(roles) != 0 {
			t.Fatalf("payload %s granted roles: %v", payload, roles)
		}
	}
}
