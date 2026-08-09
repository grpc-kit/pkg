package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const currentUserCacheControl = "private, no-store"

var currentUserSelectFields = []string{
	users.FieldID,
	users.FieldUsername,
	users.FieldNickname,
	users.FieldProfile,
	users.FieldPicture,
	users.FieldWebsite,
	users.FieldTimezone,
	users.FieldLocale,
	users.FieldUserType,
	users.FieldUserStatus,
	users.FieldGender,
	users.FieldBirthdate,
	users.FieldEmailEncrypted,
	users.FieldEmailVerified,
	users.FieldPhoneNumberEncrypted,
	users.FieldPhoneNumberVerified,
	users.FieldCreatedAt,
	users.FieldUpdatedAt,
}

// GetCurrentUser returns the self-service profile for the effective
// authenticated subject. The request intentionally cannot select a user.
func (a *KnownAdminAPI) GetCurrentUser(ctx context.Context, _ *adminv1.GetCurrentUserRequest) (*adminv1.CurrentUserProfile, error) {
	userID, err := GetUserID(ctx)
	if err != nil || userID <= 0 {
		return nil, errs.Unauthenticated(ctx).WithMessage("authenticated user id is required").Err()
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database client is unavailable").Err()
	}
	row, err := db.Users.Query().
		Select(currentUserSelectFields...).
		Where(users.IDEQ(int(userID))).
		Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("current user not found").Err()
		}
		return nil, errs.Internal(ctx).WithMessage("query current user failed").Err()
	}

	mfaEnabled, err := db.UserIdentities.Query().
		Where(
			useridentities.UserIDEQ(row.ID),
			useridentities.MfaEnabledEQ(true),
			useridentities.HasLionAuthProvidersWith(
				authproviders.CodeEQ("local"),
				authproviders.ProviderTypeEQ(int(adminv1.AuthProvider_LOCAL.Number())),
				authproviders.DeletedAtIsNil(),
			),
		).
		Exist(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("query current user MFA status failed").Err()
	}

	profile, err := a.currentUserProfile(ctx, row, mfaEnabled)
	if err != nil {
		return nil, err
	}

	// grpc-gateway forwards this metadata through the explicit response-header
	// allow-list in cfg. A native gRPC caller does not require an HTTP header.
	_ = grpc.SetHeader(ctx, metadata.Pairs("cache-control", currentUserCacheControl))
	return profile, nil
}

func (a *KnownAdminAPI) currentUserProfile(ctx context.Context, row *lion.Users, mfaEnabled bool) (*adminv1.CurrentUserProfile, error) {
	if row == nil {
		return nil, errs.Internal(ctx).WithMessage("current user row is nil").Err()
	}

	email, err := a.decryptStringField(ctx, "email", row.EmailEncrypted)
	if err != nil {
		return nil, err
	}
	phoneNumber, err := a.decryptPhoneNumberField(ctx, row.PhoneNumberEncrypted)
	if err != nil {
		return nil, err
	}

	var birthday *timestamppb.Timestamp
	if row.Birthdate != nil {
		birthday = timestamppb.New(*row.Birthdate)
	}
	return &adminv1.CurrentUserProfile{
		Id:                  int64(row.ID),
		Username:            row.Username,
		Nickname:            row.Nickname,
		Profile:             row.Profile,
		Picture:             row.Picture,
		Website:             row.Website,
		Timezone:            row.Timezone,
		Locale:              row.Locale,
		Type:                adminv1.User_Type(row.UserType),
		Status:              adminv1.User_Status(row.UserStatus),
		Gender:              adminv1.User_Gender(row.Gender),
		Birthday:            birthday,
		Email:               email,
		EmailVerified:       row.EmailVerified,
		PhoneNumber:         phoneNumber,
		PhoneNumberVerified: row.PhoneNumberVerified,
		MfaEnabled:          mfaEnabled,
		CreatedAt:           timestamppb.New(row.CreatedAt),
		UpdatedAt:           timestamppb.New(row.UpdatedAt),
		Etag:                currentUserETag(row.ID, row.UpdatedAt),
	}, nil
}

func currentUserETag(userID int, updatedAt time.Time) string {
	payload := strconv.Itoa(userID) + "\n" + updatedAt.UTC().Format(time.RFC3339Nano)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}
