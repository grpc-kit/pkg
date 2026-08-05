package cfg

import "testing"

func TestAuthorizationEffectiveAllowedRoles(t *testing.T) {
	tests := []struct {
		name       string
		authorizer Authorization
		want       []string
		consistent bool
	}{
		{
			name:       "legacy only",
			authorizer: Authorization{AllowedGroups: []string{"admin"}},
			want:       []string{"admin"},
			consistent: true,
		},
		{
			name:       "roles only",
			authorizer: Authorization{AllowedRoles: []string{"admin"}},
			want:       []string{"admin"},
			consistent: true,
		},
		{
			name:       "same sets",
			authorizer: Authorization{AllowedGroups: []string{"admin", "viewer"}, AllowedRoles: []string{"viewer", "admin"}},
			want:       []string{"viewer", "admin"},
			consistent: true,
		},
		{
			name:       "conflicting sets",
			authorizer: Authorization{AllowedGroups: []string{"admin"}, AllowedRoles: []string{"viewer"}},
			consistent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, consistent := tt.authorizer.effectiveAllowedRoles()
			if consistent != tt.consistent {
				t.Fatalf("consistent = %v, want %v", consistent, tt.consistent)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("roles = %v, want %v", got, tt.want)
			}
		})
	}
}
