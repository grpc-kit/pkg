package admin

import (
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
)

func TestSeedDepartmentCode(t *testing.T) {
	tests := []struct {
		c    adminv1.DepartmentCode
		want string
	}{
		{adminv1.DepartmentCode_DEPARTMENT_CODE_UNSPECIFIED, ""},
		{adminv1.DepartmentCode_DEPARTMENT_CODE_ROOT, "root"},
		{adminv1.DepartmentCode_DEPARTMENT_CODE_GUEST, "guest"},
	}
	for _, tt := range tests {
		if got := seedDepartmentCode(tt.c); got != tt.want {
			t.Errorf("seedDepartmentCode(%v) = %q, want %q", tt.c, got, tt.want)
		}
	}
}

func TestSeedRoleCode(t *testing.T) {
	tests := []struct {
		c    adminv1.RoleCode
		want string
	}{
		{adminv1.RoleCode_ROLE_CODE_UNSPECIFIED, ""},
		{adminv1.RoleCode_ROLE_CODE_SUPERADMIN, "superadmin"},
	}
	for _, tt := range tests {
		if got := seedRoleCode(tt.c); got != tt.want {
			t.Errorf("seedRoleCode(%v) = %q, want %q", tt.c, got, tt.want)
		}
	}
}

func TestSeedAuthProviderCode(t *testing.T) {
	tests := []struct {
		c    adminv1.AuthProviderCode
		want string
	}{
		{adminv1.AuthProviderCode_AUTH_PROVIDER_CODE_UNSPECIFIED, ""},
		{adminv1.AuthProviderCode_AUTH_PROVIDER_CODE_LOCAL, "local"},
	}
	for _, tt := range tests {
		if got := seedAuthProviderCode(tt.c); got != tt.want {
			t.Errorf("seedAuthProviderCode(%v) = %q, want %q", tt.c, got, tt.want)
		}
	}
}

func TestSeedCredentialCode(t *testing.T) {
	tests := []struct {
		c    adminv1.CredentialCode
		want string
	}{
		{adminv1.CredentialCode_CREDENTIAL_CODE_UNSPECIFIED, ""},
		{adminv1.CredentialCode_CREDENTIAL_CODE_JWT_SIGNING_V1, "jwt-signing-v1"},
	}
	for _, tt := range tests {
		if got := seedCredentialCode(tt.c); got != tt.want {
			t.Errorf("seedCredentialCode(%v) = %q, want %q", tt.c, got, tt.want)
		}
	}
}

func TestSeedBootstrapUsername(t *testing.T) {
	tests := []struct {
		c    adminv1.BootstrapUsername
		want string
	}{
		{adminv1.BootstrapUsername_BOOTSTRAP_USERNAME_UNSPECIFIED, ""},
		{adminv1.BootstrapUsername_BOOTSTRAP_USERNAME_ADMIN, "admin"},
	}
	for _, tt := range tests {
		if got := seedBootstrapUsername(tt.c); got != tt.want {
			t.Errorf("seedBootstrapUsername(%v) = %q, want %q", tt.c, got, tt.want)
		}
	}
}
