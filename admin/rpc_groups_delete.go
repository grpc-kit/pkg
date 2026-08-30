package admin

import (
	"context"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/groups"
	"github.com/grpc-kit/pkg/lion/principalroles"
	"github.com/grpc-kit/pkg/lion/usermemberships"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
)

// DeleteGroup moves a group to the recycle bin. Authorization is enforced by
// the IAM/OPA interceptor before this handler is called.
func (a *KnownAdminAPI) DeleteGroup(ctx context.Context, req *adminv1.DeleteGroupRequest) (*adminv1.Group, error) {
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
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("begin delete group transaction failed")
	}
	defer func() { _ = tx.Rollback() }()

	targetID := int(req.GetId())
	group, err := tx.Groups.Query().Where(groups.IDEQ(targetID), groups.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("group not found")
		}
		return nil, errs.Internal(ctx).WithMessage("query group failed")
	}
	if err := ensureGroupDeleteAllowed(ctx, tx, group); err != nil {
		return nil, err
	}

	affected, err := tx.Groups.Update().
		Where(groups.IDEQ(targetID), groups.DeletedAtIsNil()).
		SetDeletedAt(time.Now()).
		SetGroupStatus(int(adminv1.Group_DISABLED)).
		SetUpdatedBy(actorID).
		Save(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("soft delete group failed")
	}
	if affected != 1 {
		return nil, errs.NotFound(ctx).WithMessage("group not found")
	}
	if err := tx.Commit(); err != nil {
		return nil, errs.Internal(ctx).WithMessage("commit delete group failed")
	}

	row, err := db.Groups.Query().Where(groups.IDEQ(targetID)).Only(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("read deleted group failed")
	}
	result, err := groupToProto(row, true)
	if err != nil {
		return nil, errs.FailedPrecondition(ctx).WithMessage(err.Error())
	}
	return result, nil
}

// UndeleteGroup restores a group from the recycle bin. Restored groups remain
// disabled and require an explicit UpdateGroup operation to become active.
func (a *KnownAdminAPI) UndeleteGroup(ctx context.Context, req *adminv1.UndeleteGroupRequest) (*adminv1.Group, error) {
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
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("begin undelete group transaction failed")
	}
	defer func() { _ = tx.Rollback() }()

	targetID := int(req.GetId())
	group, err := tx.Groups.Query().Where(groups.IDEQ(targetID), groups.DeletedAtNotNil()).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			exists, existsErr := tx.Groups.Query().Where(groups.IDEQ(targetID)).Exist(ctx)
			if existsErr != nil {
				return nil, errs.Internal(ctx).WithMessage("query group failed")
			}
			if exists {
				return nil, errs.AlreadyExists(ctx).WithMessage("group is not deleted")
			}
			return nil, errs.NotFound(ctx).WithMessage("group not found")
		}
		return nil, errs.Internal(ctx).WithMessage("query group failed")
	}
	if group.ParentID != 0 {
		parentExists, err := tx.Groups.Query().Where(groups.IDEQ(group.ParentID), groups.DeletedAtIsNil()).Exist(ctx)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage("query group parent failed")
		}
		if !parentExists {
			return nil, errs.FailedPrecondition(ctx).WithMessage("group parent must be restored before undelete")
		}
	}

	affected, err := tx.Groups.Update().
		Where(groups.IDEQ(targetID), groups.DeletedAtNotNil()).
		ClearDeletedAt().
		SetGroupStatus(int(adminv1.Group_DISABLED)).
		SetUpdatedBy(actorID).
		Save(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("undelete group failed")
	}
	if affected != 1 {
		return nil, errs.NotFound(ctx).WithMessage("group not found")
	}
	if err := tx.Commit(); err != nil {
		return nil, errs.Internal(ctx).WithMessage("commit undelete group failed")
	}

	row, err := db.Groups.Query().Where(groups.IDEQ(targetID)).Only(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("read restored group failed")
	}
	result, err := groupToProto(row, true)
	if err != nil {
		return nil, errs.FailedPrecondition(ctx).WithMessage(err.Error())
	}
	return result, nil
}

// ExpungeGroup irreversibly removes a soft-deleted group and the core rows
// that reference it. Authorization is enforced by the IAM/OPA interceptor.
func (a *KnownAdminAPI) ExpungeGroup(ctx context.Context, req *adminv1.ExpungeGroupRequest) (*emptypb.Empty, error) {
	if req == nil || req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("id is invalid")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database unavailable")
	}
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("begin expunge group transaction failed")
	}
	defer func() { _ = tx.Rollback() }()

	targetID := int(req.GetId())
	group, err := tx.Groups.Query().Where(groups.IDEQ(targetID), groups.DeletedAtNotNil()).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			exists, existsErr := tx.Groups.Query().Where(groups.IDEQ(targetID)).Exist(ctx)
			if existsErr != nil {
				return nil, errs.Internal(ctx).WithMessage("query group failed")
			}
			if exists {
				return nil, errs.FailedPrecondition(ctx).WithMessage("group must be soft-deleted before expunge")
			}
			return nil, errs.NotFound(ctx).WithMessage("group not found")
		}
		return nil, errs.Internal(ctx).WithMessage("query group failed")
	}
	if err := ensureGroupExpungeAllowed(ctx, tx, group); err != nil {
		return nil, err
	}

	for _, cleanup := range []func() error{
		func() error {
			_, err := tx.UserMemberships.Delete().Where(
				usermemberships.TargetTypeEQ(membershipTargetGroup),
				usermemberships.TargetIDEQ(targetID),
			).Exec(ctx)
			return err
		},
		// Valid Role bindings can reference only protected SYSTEM groups, which
		// cannot reach this expunge path. Keep this cleanup for legacy or
		// out-of-band invalid GROUP bindings so expunge never leaves orphans.
		func() error {
			_, err := tx.PrincipalRoles.Delete().Where(
				principalroles.PrincipalTypeEQ(principalTypeGroup),
				principalroles.PrincipalIDEQ(targetID),
			).Exec(ctx)
			return err
		},
	} {
		if err := cleanup(); err != nil {
			return nil, errs.Internal(ctx).WithMessage("clean group dependent data failed")
		}
	}
	affected, err := tx.Groups.Delete().Where(groups.IDEQ(targetID), groups.DeletedAtNotNil()).Exec(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("expunge group failed")
	}
	if affected != 1 {
		return nil, errs.NotFound(ctx).WithMessage("group not found")
	}
	if err := tx.Commit(); err != nil {
		return nil, errs.Internal(ctx).WithMessage("commit expunge group failed")
	}
	return &emptypb.Empty{}, nil
}

func ensureGroupDeleteAllowed(ctx context.Context, tx *lion.Tx, group *lion.Groups) error {
	if group.Protected || adminv1.Group_Type(group.GroupType) == adminv1.Group_SYSTEM {
		return errs.FailedPrecondition(ctx).WithMessage("protected group cannot be deleted")
	}
	hasChildren, err := tx.Groups.Query().Where(groups.ParentIDEQ(group.ID)).Exist(ctx)
	if err != nil {
		return errs.Internal(ctx).WithMessage("query group children failed")
	}
	if hasChildren {
		return errs.FailedPrecondition(ctx).WithMessage("group with children cannot be deleted")
	}
	return nil
}

func ensureGroupExpungeAllowed(ctx context.Context, tx *lion.Tx, group *lion.Groups) error {
	if group.Protected || adminv1.Group_Type(group.GroupType) == adminv1.Group_SYSTEM {
		return errs.FailedPrecondition(ctx).WithMessage("protected group cannot be expunged")
	}
	hasChildren, err := tx.Groups.Query().Where(groups.ParentIDEQ(group.ID)).Exist(ctx)
	if err != nil {
		return errs.Internal(ctx).WithMessage("query group children failed")
	}
	if hasChildren {
		return errs.FailedPrecondition(ctx).WithMessage("group with children cannot be expunged")
	}
	return nil
}
