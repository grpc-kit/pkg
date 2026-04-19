package admin

import (
	"strings"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
)

// 与 code.pb.go 中 *_name 取值前缀一致；新增枚举值时保持「前缀 + 全大写蛇形」，
// 去前缀后 ToLower 并将 '_' 换为 '-'，与 admin.common.proto Resource.code（kebab-case）一致。
const (
	prefixDepartmentCode     = "DEPARTMENT_CODE_"
	prefixRoleCode           = "ROLE_CODE_"
	prefixAuthProviderCode   = "AUTH_PROVIDER_CODE_"
	prefixResourceSeedCode   = "RESOURCE_SEED_CODE_"
	prefixCredentialSeedCode = "CREDENTIAL_SEED_CODE_"
	prefixBootstrapUsername  = "BOOTSTRAP_USERNAME_"
)

// codeFromEnumName 将 protobuf 枚举符号名（如 RESOURCE_SEED_CODE_ROOT_DOMAIN）转为种子使用的字符串（root-domain）。
func codeFromEnumName(prefix, full string) string {
	if full == "" {
		return ""
	}
	if !strings.HasPrefix(full, prefix) {
		return ""
	}
	tail := strings.TrimPrefix(full, prefix)
	if tail == "" || tail == "UNSPECIFIED" {
		return ""
	}
	return strings.ReplaceAll(strings.ToLower(tail), "_", "-")
}

func seedFromEnumName(nameMap map[int32]string, prefix string, n int32) string {
	full, ok := nameMap[n]
	if !ok {
		return ""
	}
	return codeFromEnumName(prefix, full)
}

func seedDepartmentCode(c adminv1.DepartmentCode) string {
	return seedFromEnumName(adminv1.DepartmentCode_name, prefixDepartmentCode, int32(c))
}

func seedRoleCode(c adminv1.RoleCode) string {
	return seedFromEnumName(adminv1.RoleCode_name, prefixRoleCode, int32(c))
}

func seedAuthProviderCode(c adminv1.AuthProviderCode) string {
	return seedFromEnumName(adminv1.AuthProviderCode_name, prefixAuthProviderCode, int32(c))
}

func seedResourceSeedCode(c adminv1.ResourceSeedCode) string {
	return seedFromEnumName(adminv1.ResourceSeedCode_name, prefixResourceSeedCode, int32(c))
}

func seedCredentialSeedCode(c adminv1.CredentialSeedCode) string {
	return seedFromEnumName(adminv1.CredentialSeedCode_name, prefixCredentialSeedCode, int32(c))
}

func seedBootstrapUsername(c adminv1.BootstrapUsername) string {
	return seedFromEnumName(adminv1.BootstrapUsername_name, prefixBootstrapUsername, int32(c))
}
