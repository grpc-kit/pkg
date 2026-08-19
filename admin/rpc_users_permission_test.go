package admin

import (
	"context"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func userManagementContext(userID int64, roleCode string) context.Context {
	ctx := rpc.ContextWithUserID(context.Background(), userID)
	if roleCode != "" {
		ctx = rpc.ContextWithRoles(ctx, []string{roleCode})
	}
	return ctx
}

func TestRequireUserManagePermissionRoleBoundary(t *testing.T) {
	tests := []struct {
		name     string
		roleCode string
		allowed  bool
	}{
		{name: "superadmin", roleCode: seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN), allowed: true},
		{name: "admin", roleCode: seedRoleCode(adminv1.RoleCode_ROLE_CODE_ADMIN), allowed: true},
		{name: "user", roleCode: seedRoleCode(adminv1.RoleCode_ROLE_CODE_USER), allowed: false},
		{name: "guest", roleCode: seedRoleCode(adminv1.RoleCode_ROLE_CODE_GUEST), allowed: false},
		{name: "missing role", allowed: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newMFATestAPI()
			gotUserID, err := a.requireUserManagePermission(
				userManagementContext(42, tc.roleCode),
				permissionUsersUpdate,
			)
			if tc.allowed {
				if err != nil || gotUserID != 42 {
					t.Fatalf("expected permission, got userID=%d err=%v", gotUserID, err)
				}
				return
			}
			if err == nil || errs.FromError(err).HTTPStatusCode() != 403 {
				t.Fatalf("expected 403, got userID=%d err=%v", gotUserID, err)
			}
		})
	}
}

func TestUpdateUserRejectsServerManagedFieldsBeforeDatabaseAccess(t *testing.T) {
	restrictedPaths := []string{
		"created_by",
		"updated_by",
		"created_at",
		"updated_at",
		"deleted_at",
	}

	for _, path := range restrictedPaths {
		t.Run(path, func(t *testing.T) {
			a := newMFATestAPI()
			ctx := userManagementContext(42, seedRoleCode(adminv1.RoleCode_ROLE_CODE_ADMIN))
			_, err := a.UpdateUser(ctx, &adminv1.UpdateUserRequest{
				User:       &adminv1.User{Id: 100},
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{path}},
			})
			if err == nil || errs.FromError(err).HTTPStatusCode() != 400 {
				t.Fatalf("expected 400 for %s, got %v", path, err)
			}
		})
	}
}

// TestUpdateUserAcceptsVerificationFlagPaths 固化管理端可人工置位验证状态的约定：
// email_verified / phone_number_verified 不再被 update_mask 前置校验拒绝。
func TestUpdateUserAcceptsVerificationFlagPaths(t *testing.T) {
	for _, path := range []string{"email_verified", "phone_number_verified"} {
		t.Run(path, func(t *testing.T) {
			if isServerManagedUserField(path) {
				t.Fatalf("%s should be writable by user management", path)
			}
		})
	}
}

func TestUserManagementRPCsRejectOrdinaryRoleBeforeDatabaseAccess(t *testing.T) {
	a := newMFATestAPI()
	ctx := userManagementContext(42, seedRoleCode(adminv1.RoleCode_ROLE_CODE_USER))
	tests := []struct {
		name string
		call func() error
	}{
		{name: "list basic", call: func() error {
			_, err := a.ListUsers(ctx, &adminv1.ListUsersRequest{})
			return err
		}},
		{name: "list full", call: func() error {
			_, err := a.ListUsers(ctx, &adminv1.ListUsersRequest{View: adminv1.ListUsersRequest_USER_VIEW_FULL})
			return err
		}},
		{name: "get", call: func() error {
			_, err := a.GetUser(ctx, &adminv1.GetUserRequest{Id: 100})
			return err
		}},
		{name: "create", call: func() error {
			_, err := a.CreateUser(ctx, &adminv1.CreateUserRequest{User: &adminv1.User{Username: "alice"}})
			return err
		}},
		{name: "update", call: func() error {
			_, err := a.UpdateUser(ctx, &adminv1.UpdateUserRequest{
				User:       &adminv1.User{Id: 100, Nickname: "Alice"},
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"nickname"}},
			})
			return err
		}},
		{name: "reset password", call: func() error {
			_, err := a.UpdateUserPassword(ctx, &adminv1.UpdateUserPasswordRequest{UserId: 100, NewPasswordHash: "hash"})
			return err
		}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil || errs.FromError(err).HTTPStatusCode() != 403 {
				t.Fatalf("expected 403, got %v", err)
			}
		})
	}
}
