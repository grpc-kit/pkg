package admin

import (
	"context"
	"fmt"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
)

func immutableFieldError(ctx context.Context, resource, field string) error {
	return errs.InvalidArgument(ctx).
		WithMessage(fmt.Sprintf("%s %s is immutable after creation", resource, field)).Err()
}

func validateImmutableString(ctx context.Context, resource, field, current, requested string) error {
	if requested != current {
		return immutableFieldError(ctx, resource, field)
	}
	return nil
}

func isBuiltinRoleCode(code string) bool {
	return code == seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN) ||
		code == seedRoleCode(adminv1.RoleCode_ROLE_CODE_ADMIN) ||
		code == seedRoleCode(adminv1.RoleCode_ROLE_CODE_USER) ||
		code == seedRoleCode(adminv1.RoleCode_ROLE_CODE_GUEST)
}

func isBuiltinDepartmentCode(code string) bool {
	switch code {
	case "root", "builtin", "admin", "unassigned":
		return true
	default:
		return false
	}
}
