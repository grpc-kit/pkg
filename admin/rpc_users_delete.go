package admin

import (
	"context"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/oauth2codes"
	"github.com/grpc-kit/pkg/lion/principalroles"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/usermemberships"
	"github.com/grpc-kit/pkg/lion/userprofiles"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/protobuf/types/known/emptypb"
)

// DeleteUser moves a user to the recycle bin. Authorization is enforced by
// the IAM/OPA interceptor before this handler is called.
func (a *KnownAdminAPI) DeleteUser(ctx context.Context, req *adminv1.DeleteUserRequest) (*adminv1.User, error) {
	if req == nil || req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("id is invalid")
	}
	actorID, err := GetUserID(ctx)
	if err != nil || actorID <= 0 {
		return nil, errs.PermissionDenied(ctx).WithMessage("authenticated user id is required")
	}
	if actorID == req.GetId() {
		return nil, errs.FailedPrecondition(ctx).WithMessage("cannot delete yourself")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database unavailable")
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("begin delete user transaction failed")
	}
	defer func() { _ = tx.Rollback() }()

	targetID := int(req.GetId())
	target, err := tx.Users.Query().Where(users.IDEQ(targetID), users.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("user not found")
		}
		return nil, errs.Internal(ctx).WithMessage("query user failed")
	}
	if err := a.ensureDeleteLeavesSuperadmin(ctx, tx, target); err != nil {
		return nil, err
	}

	affected, err := tx.Users.Update().
		Where(users.IDEQ(targetID), users.DeletedAtIsNil()).
		SetDeletedAt(time.Now()).
		SetUserStatus(int(adminv1.User_DISABLED)).
		SetUpdatedBy(actorID).
		Save(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("soft delete user failed")
	}
	if affected != 1 {
		return nil, errs.NotFound(ctx).WithMessage("user not found")
	}
	if _, err := tx.OAuth2Codes.Delete().Where(oauth2codes.UserIDEQ(targetID)).Exec(ctx); err != nil {
		return nil, errs.Internal(ctx).WithMessage("clear user oauth2 codes failed")
	}
	if err := tx.Commit(); err != nil {
		return nil, errs.Internal(ctx).WithMessage("commit delete user failed")
	}

	a.mfaChallenges.DeleteByUserID(targetID)
	row, err := db.Users.Query().Where(users.IDEQ(targetID)).Only(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("read deleted user failed")
	}
	return a.toAdminUser(ctx, row, true)
}

// UndeleteUser restores a user from the recycle bin. Restored users remain
// disabled and require an explicit UpdateUser operation to become active.
func (a *KnownAdminAPI) UndeleteUser(ctx context.Context, req *adminv1.UndeleteUserRequest) (*adminv1.User, error) {
	if req == nil || req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("id is invalid")
	}
	actorID, err := GetUserID(ctx)
	if err != nil || actorID <= 0 {
		return nil, errs.PermissionDenied(ctx).WithMessage("authenticated user id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database unavailable")
	}
	targetID := int(req.GetId())
	affected, err := db.Users.Update().
		Where(users.IDEQ(targetID), users.DeletedAtNotNil()).
		ClearDeletedAt().
		SetUserStatus(int(adminv1.User_DISABLED)).
		SetUpdatedBy(actorID).
		Save(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("undelete user failed")
	}
	if affected == 0 {
		exists, err := db.Users.Query().Where(users.IDEQ(targetID)).Exist(ctx)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage("query user failed")
		}
		if exists {
			return nil, errs.AlreadyExists(ctx).WithMessage("user is not deleted")
		}
		return nil, errs.NotFound(ctx).WithMessage("user not found")
	}

	row, err := db.Users.Query().Where(users.IDEQ(targetID)).Only(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("read restored user failed")
	}
	return a.toAdminUser(ctx, row, true)
}

// ExpungeUser irreversibly removes a soft-deleted user and the core rows that
// reference it. Authorization is enforced by the IAM/OPA interceptor.
func (a *KnownAdminAPI) ExpungeUser(ctx context.Context, req *adminv1.ExpungeUserRequest) (*emptypb.Empty, error) {
	if req == nil || req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("id is invalid")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database unavailable")
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("begin expunge user transaction failed")
	}
	defer func() { _ = tx.Rollback() }()

	targetID := int(req.GetId())
	deleted, err := tx.Users.Query().Where(users.IDEQ(targetID), users.DeletedAtNotNil()).Exist(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("query user failed")
	}
	if !deleted {
		exists, err := tx.Users.Query().Where(users.IDEQ(targetID)).Exist(ctx)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage("query user failed")
		}
		if exists {
			return nil, errs.FailedPrecondition(ctx).WithMessage("user must be soft-deleted before expunge")
		}
		return nil, errs.NotFound(ctx).WithMessage("user not found")
	}

	for _, cleanup := range []func() error{
		func() error {
			_, err := tx.UserIdentities.Delete().Where(useridentities.UserIDEQ(targetID)).Exec(ctx)
			return err
		},
		func() error {
			_, err := tx.UserMemberships.Delete().Where(usermemberships.UserIDEQ(targetID)).Exec(ctx)
			return err
		},
		func() error {
			_, err := tx.UserProfiles.Delete().Where(userprofiles.UserIDEQ(targetID)).Exec(ctx)
			return err
		},
		func() error {
			_, err := tx.PrincipalRoles.Delete().Where(
				principalroles.PrincipalTypeEQ(principalTypeUser),
				principalroles.PrincipalIDEQ(targetID),
			).Exec(ctx)
			return err
		},
		func() error {
			_, err := tx.OAuth2Codes.Delete().Where(oauth2codes.UserIDEQ(targetID)).Exec(ctx)
			return err
		},
	} {
		if err := cleanup(); err != nil {
			return nil, errs.Internal(ctx).WithMessage("clean user dependent data failed")
		}
	}
	affected, err := tx.Users.Delete().Where(users.IDEQ(targetID), users.DeletedAtNotNil()).Exec(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("expunge user failed")
	}
	if affected != 1 {
		return nil, errs.NotFound(ctx).WithMessage("user not found")
	}
	if err := tx.Commit(); err != nil {
		return nil, errs.Internal(ctx).WithMessage("commit expunge user failed")
	}
	a.mfaChallenges.DeleteByUserID(targetID)
	return &emptypb.Empty{}, nil
}

// ensureDeleteLeavesSuperadmin serializes DeleteUser requests on the
// superadmin role row and prevents the last active database superadmin from
// being deleted. Role membership includes direct, group, and department
// bindings through the existing effective-role resolver.
func (a *KnownAdminAPI) ensureDeleteLeavesSuperadmin(ctx context.Context, tx *lion.Tx, target *lion.Users) error {
	superadmin, err := tx.Roles.Query().Where(roles.CodeEQ(seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN))).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil
		}
		return errs.Internal(ctx).WithMessage("query superadmin role failed")
	}
	// Ent generation in this module has no ForUpdate helper. A no-op update on
	// the common role row takes the database row lock for this transaction and
	// serializes the following last-superadmin check across API instances.
	if _, err := tx.Roles.Update().Where(roles.IDEQ(superadmin.ID)).SetUpdatedAt(superadmin.UpdatedAt).Save(ctx); err != nil {
		return errs.Internal(ctx).WithMessage("lock superadmin role failed")
	}

	now := time.Now()
	targetRoles, err := effectiveRoleIDsForUserAt(ctx, tx.Client(), target.ID, now)
	if err != nil {
		return errs.Internal(ctx).WithMessage("resolve target roles failed")
	}
	if !containsInt(targetRoles, superadmin.ID) {
		return nil
	}

	candidates, err := tx.Users.Query().
		Select(users.FieldID).
		Where(users.UserStatusEQ(int(adminv1.User_ACTIVE)), users.DeletedAtIsNil()).
		All(ctx)
	if err != nil {
		return errs.Internal(ctx).WithMessage("query active users failed")
	}
	for _, candidate := range candidates {
		if candidate.ID == target.ID {
			continue
		}
		roleIDs, err := effectiveRoleIDsForUserAt(ctx, tx.Client(), candidate.ID, now)
		if err != nil {
			return errs.Internal(ctx).WithMessage("resolve active user roles failed")
		}
		if containsInt(roleIDs, superadmin.ID) {
			return nil
		}
	}
	return errs.FailedPrecondition(ctx).WithMessage("cannot delete the last active superadmin")
}

func containsInt(values []int, wanted int) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
