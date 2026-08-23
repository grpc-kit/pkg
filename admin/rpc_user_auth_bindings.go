package admin

import (
	"context"
	"sort"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func optionalUserAuthBindingTimestamp(value *time.Time) *timestamppb.Timestamp {
	if value == nil || value.IsZero() {
		return nil
	}
	return timestamppb.New(*value)
}

func userAuthBindingTimestamp(value time.Time) *timestamppb.Timestamp {
	return optionalUserAuthBindingTimestamp(&value)
}

func projectUserAuthBindings(ctx context.Context, identities []*lion.UserIdentities) ([]*adminv1.UserAuthBinding, error) {
	bindings := make([]*adminv1.UserAuthBinding, 0, len(identities))
	ordered := append([]*lion.UserIdentities(nil), identities...)

	for _, identity := range ordered {
		if identity == nil || identity.Edges.LionAuthProviders == nil {
			return nil, errs.Internal(ctx).WithMessage("authentication provider is unavailable").Err()
		}
	}

	sort.SliceStable(ordered, func(i, j int) bool {
		leftProvider := ordered[i].Edges.LionAuthProviders
		rightProvider := ordered[j].Edges.LionAuthProviders
		if leftProvider.SortOrder != rightProvider.SortOrder {
			return leftProvider.SortOrder < rightProvider.SortOrder
		}
		if leftProvider.ID != rightProvider.ID {
			return leftProvider.ID < rightProvider.ID
		}
		return ordered[i].ID < ordered[j].ID
	})

	for _, identity := range ordered {
		provider := identity.Edges.LionAuthProviders
		passwordConfigured := identity.PasswordHash != ""
		bindings = append(bindings, &adminv1.UserAuthBinding{
			Id:                  int64(identity.ID),
			UserId:              int64(identity.UserID),
			ProviderId:          int64(provider.ID),
			ProviderCode:        provider.Code,
			ProviderDisplayName: provider.DisplayName,
			ProviderType:        adminv1.AuthProvider_Type(provider.ProviderType),
			ProviderStatus:      adminv1.AuthProvider_Status(provider.ProviderStatus),
			ProviderIconUrl:     provider.IconURL,
			ProviderUserId:      identity.ProviderUserID,
			ProviderUnionId:     identity.ProviderUnionID,
			PasswordConfigured:  passwordConfigured,
			MfaEnabled:          identity.MfaEnabled,
			PasswordChangedAt:   optionalUserAuthBindingTimestamp(identity.PasswordChangedAt),
			PasswordExpiresAt:   optionalUserAuthBindingTimestamp(identity.PasswordExpiresAt),
			LastLoginAt:         optionalUserAuthBindingTimestamp(identity.LastLoginAt),
			CreatedAt:           userAuthBindingTimestamp(identity.CreatedAt),
			UpdatedAt:           userAuthBindingTimestamp(identity.UpdatedAt),
		})
	}

	return bindings, nil
}

// ListUserAuthBindings returns the read-only authentication identity summary
// for one managed user. Method-level IAM/OPA authorization runs before this
// handler; this method intentionally contains no parallel role or permission
// checks.
func (a *KnownAdminAPI) ListUserAuthBindings(ctx context.Context, req *adminv1.ListUserAuthBindingsRequest) (*adminv1.ListUserAuthBindingsResponse, error) {
	if req == nil || req.GetUserId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("user_id must be greater than zero").Err()
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("not found database client").Err()
	}
	userID := int(req.GetUserId())

	exists, err := db.Users.Query().
		Select(users.FieldID).
		Where(users.IDEQ(userID)).
		Exist(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("query user failed").Err()
	}
	if !exists {
		return nil, errs.NotFound(ctx).WithMessage("user not found").Err()
	}

	identities, err := db.UserIdentities.Query().
		Select(
			useridentities.FieldID,
			useridentities.FieldUserID,
			useridentities.FieldProviderID,
			useridentities.FieldProviderUserID,
			useridentities.FieldProviderUnionID,
			useridentities.FieldPasswordHash,
			useridentities.FieldMfaEnabled,
			useridentities.FieldPasswordChangedAt,
			useridentities.FieldPasswordExpiresAt,
			useridentities.FieldLastLoginAt,
			useridentities.FieldCreatedAt,
			useridentities.FieldUpdatedAt,
		).
		Where(useridentities.UserIDEQ(userID)).
		WithLionAuthProviders(func(query *lion.AuthProvidersQuery) {
			query.Select(
				authproviders.FieldID,
				authproviders.FieldCode,
				authproviders.FieldDisplayName,
				authproviders.FieldProviderType,
				authproviders.FieldProviderStatus,
				authproviders.FieldSortOrder,
				authproviders.FieldIconURL,
			)
		}).
		All(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("query user authentication bindings failed").Err()
	}

	bindings, err := projectUserAuthBindings(ctx, identities)
	if err != nil {
		return nil, err
	}
	return &adminv1.ListUserAuthBindingsResponse{Bindings: bindings}, nil
}
