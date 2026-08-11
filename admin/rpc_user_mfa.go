package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/protobuf/types/known/emptypb"
)

// DeleteUserMFA removes every MFA enrollment associated with a managed user.
// Authorization for this administrative operation is enforced by the policy
// layer before the RPC handler is invoked.
func (a *KnownAdminAPI) DeleteUserMFA(ctx context.Context, req *adminv1.DeleteUserMFARequest) (*emptypb.Empty, error) {
	if req == nil || req.GetUserId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("user_id is invalid")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database unavailable")
	}

	userID := int(req.GetUserId())
	exists, err := db.Users.Query().Where(users.IDEQ(userID)).Exist(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to query user")
	}
	if !exists {
		return nil, errs.NotFound(ctx).WithMessage("user not found")
	}

	_, err = db.UserIdentities.Update().
		Where(useridentities.UserIDEQ(userID)).
		SetMfaEnabled(false).
		SetMfaSecretEncrypted([]byte{}).
		SetMfaRecoveryCodesEncrypted([]byte{}).
		Save(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to reset user MFA")
	}

	a.mfaChallenges.DeleteByUserID(userID)
	return &emptypb.Empty{}, nil
}
