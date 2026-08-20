package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
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
		Where(users.IDEQ(int(userID)), users.UserStatusEQ(int(adminv1.User_ACTIVE)), users.DeletedAtIsNil()).
		Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("current user not found").Err()
		}
		return nil, errs.Internal(ctx).WithMessage("query current user failed").Err()
	}

	profile, err := a.buildCurrentUserProfile(ctx, db, row)
	if err != nil {
		return nil, err
	}

	// grpc-gateway forwards this metadata through the explicit response-header
	// allow-list in cfg. A native gRPC caller does not require an HTTP header.
	_ = grpc.SetHeader(ctx, metadata.Pairs("cache-control", currentUserCacheControl))
	return profile, nil
}

func (a *KnownAdminAPI) buildCurrentUserProfile(ctx context.Context, db *lion.Client, row *lion.Users) (*adminv1.CurrentUserProfile, error) {
	mfaEnabled, err := db.UserIdentities.Query().Where(
		useridentities.UserIDEQ(row.ID), useridentities.MfaEnabledEQ(true),
		useridentities.HasLionAuthProvidersWith(authproviders.CodeEQ("local"), authproviders.ProviderTypeEQ(int(adminv1.AuthProvider_LOCAL.Number())), authproviders.DeletedAtIsNil()),
	).Exist(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("query current user MFA status failed").Err()
	}
	passwordSupported, err := db.UserIdentities.Query().Where(
		useridentities.UserIDEQ(row.ID), useridentities.PasswordHashNEQ(""),
		useridentities.HasLionAuthProvidersWith(authproviders.CodeEQ("local"), authproviders.ProviderTypeEQ(int(adminv1.AuthProvider_LOCAL.Number())), authproviders.ProviderStatusEQ(int(adminv1.AuthProvider_ACTIVE.Number())), authproviders.DeletedAtIsNil()),
	).Exist(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("query current user password capability failed").Err()
	}
	profile, err := a.currentUserProfile(ctx, row, mfaEnabled)
	if err != nil {
		return nil, err
	}
	profile.PasswordChangeSupported = passwordSupported
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

var sha256HexPattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// UpdateCurrentUser changes only the authenticated subject's editable profile.
func (a *KnownAdminAPI) UpdateCurrentUser(ctx context.Context, req *adminv1.UpdateCurrentUserRequest) (*adminv1.CurrentUserProfile, error) {
	userID, err := GetUserID(ctx)
	if err != nil || userID <= 0 {
		return nil, errs.Unauthenticated(ctx).WithMessage("authenticated user id is required").Err()
	}
	if req == nil || req.Profile == nil || req.Etag == "" || req.UpdateMask == nil || len(req.UpdateMask.Paths) == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("profile, update_mask and etag are required").Err()
	}
	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database client is unavailable").Err()
	}
	row, err := db.Users.Query().Select(currentUserSelectFields...).Where(users.IDEQ(int(userID)), users.UserStatusEQ(int(adminv1.User_ACTIVE)), users.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("current user not found").Err()
		}
		return nil, errs.Internal(ctx).WithMessage("query current user failed").Err()
	}
	if req.Etag != currentUserETag(row.ID, row.UpdatedAt) {
		return nil, errs.Aborted(ctx).WithErrorInfo("CURRENT_USER_ETAG_MISMATCH", "grpc-kit.com", nil).WithMessage("current user profile has changed; refresh and retry").Err()
	}
	update := db.Users.Update().Where(users.IDEQ(row.ID), users.UpdatedAtEQ(row.UpdatedAt), users.UserStatusEQ(int(adminv1.User_ACTIVE)), users.DeletedAtIsNil())
	seen := map[string]bool{}
	for _, path := range req.UpdateMask.Paths {
		if seen[path] {
			return nil, errs.InvalidArgument(ctx).WithMessage("update_mask contains duplicate path").Err()
		}
		seen[path] = true
		switch path {
		case "nickname":
			if len(req.Profile.Nickname) > 255 {
				return nil, errs.InvalidArgument(ctx).WithMessage("nickname is too long").Err()
			}
			update.SetNickname(req.Profile.Nickname)
		case "profile":
			if len(req.Profile.Profile) > 500 {
				return nil, errs.InvalidArgument(ctx).WithMessage("profile is too long").Err()
			}
			update.SetProfile(req.Profile.Profile)
		case "picture":
			if err := validateCurrentUserURL(req.Profile.Picture); err != nil {
				return nil, err
			}
			if req.Profile.Picture == "" {
				update.ClearPicture()
			} else {
				update.SetPicture(req.Profile.Picture)
			}
		case "website":
			if err := validateCurrentUserURL(req.Profile.Website); err != nil {
				return nil, err
			}
			if req.Profile.Website == "" {
				update.ClearWebsite()
			} else {
				update.SetWebsite(req.Profile.Website)
			}
		case "timezone":
			if req.Profile.Timezone != "" {
				if _, err := time.LoadLocation(req.Profile.Timezone); err != nil {
					return nil, errs.InvalidArgument(ctx).WithMessage("timezone is invalid").Err()
				}
			}
			update.SetTimezone(req.Profile.Timezone)
		case "locale":
			if len(req.Profile.Locale) > 35 {
				return nil, errs.InvalidArgument(ctx).WithMessage("locale is too long").Err()
			}
			update.SetLocale(req.Profile.Locale)
		case "gender":
			if !isSupportedGender(req.Profile.Gender) {
				return nil, errs.InvalidArgument(ctx).WithMessage("gender is invalid").Err()
			}
			update.SetGender(int(req.Profile.Gender))
		case "birthday":
			if req.Profile.Birthday == nil {
				update.ClearBirthdate()
			} else {
				if err := req.Profile.Birthday.CheckValid(); err != nil {
					return nil, errs.InvalidArgument(ctx).WithMessage("birthday is invalid").Err()
				}
				birthday := req.Profile.Birthday.AsTime()
				if birthday.Before(time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)) || birthday.After(time.Now()) {
					return nil, errs.InvalidArgument(ctx).WithMessage("birthday is outside the allowed range").Err()
				}
				update.SetBirthdate(birthday)
			}
		default:
			return nil, errs.InvalidArgument(ctx).WithMessage("update_mask contains an unsupported path").Err()
		}
	}
	affected, err := update.Save(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("update current user failed").Err()
	}
	if affected == 0 {
		return nil, errs.Aborted(ctx).WithErrorInfo("CURRENT_USER_ETAG_MISMATCH", "grpc-kit.com", nil).WithMessage("current user profile has changed; refresh and retry").Err()
	}
	row, err = db.Users.Query().Select(currentUserSelectFields...).Where(users.IDEQ(int(userID)), users.UserStatusEQ(int(adminv1.User_ACTIVE)), users.DeletedAtIsNil()).Only(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("read updated current user failed").Err()
	}
	profile, err := a.buildCurrentUserProfile(ctx, db, row)
	if err != nil {
		return nil, err
	}
	_ = grpc.SetHeader(ctx, metadata.Pairs("cache-control", currentUserCacheControl))
	return profile, nil
}

func validateCurrentUserURL(value string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return errs.InvalidArgument(context.Background()).WithMessage("URL must use http or https").Err()
	}
	return nil
}

// ChangeCurrentUserPassword updates an existing active LOCAL identity only.
func (a *KnownAdminAPI) ChangeCurrentUserPassword(ctx context.Context, req *adminv1.ChangeCurrentUserPasswordRequest) (*emptypb.Empty, error) {
	userID, err := GetUserID(ctx)
	if err != nil || userID <= 0 {
		return nil, errs.Unauthenticated(ctx).WithMessage("authenticated user id is required").Err()
	}
	if req == nil || !sha256HexPattern.MatchString(req.CurrentPasswordHash) || !sha256HexPattern.MatchString(req.NewPasswordHash) || strings.EqualFold(req.CurrentPasswordHash, req.NewPasswordHash) {
		return nil, errs.InvalidArgument(ctx).WithMessage("valid distinct current_password_hash and new_password_hash are required").Err()
	}
	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("database client is unavailable").Err()
	}
	active, err := db.Users.Query().Where(users.IDEQ(int(userID)), users.UserStatusEQ(int(adminv1.User_ACTIVE)), users.DeletedAtIsNil()).Exist(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("query current user failed").Err()
	}
	if !active {
		return nil, errs.NotFound(ctx).WithMessage("current user not found").Err()
	}
	identity, err := db.UserIdentities.Query().Where(useridentities.UserIDEQ(int(userID)), useridentities.PasswordHashNEQ(""), useridentities.HasLionAuthProvidersWith(authproviders.CodeEQ("local"), authproviders.ProviderTypeEQ(int(adminv1.AuthProvider_LOCAL.Number())), authproviders.ProviderStatusEQ(int(adminv1.AuthProvider_ACTIVE.Number())), authproviders.DeletedAtIsNil())).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.FailedPrecondition(ctx).WithErrorInfo("PASSWORD_CHANGE_NOT_SUPPORTED", "grpc-kit.com", nil).WithMessage("current account has no active local password identity").Err()
		}
		return nil, errs.Internal(ctx).WithMessage("query local password identity failed").Err()
	}
	if crypto.BcryptCompare(identity.PasswordHash, req.CurrentPasswordHash) != nil {
		return nil, errs.PermissionDenied(ctx).WithErrorInfo("CURRENT_PASSWORD_INCORRECT", "grpc-kit.com", nil).WithMessage("current password is incorrect").Err()
	}
	if _, err := db.UserIdentities.Update().Where(useridentities.IDEQ(identity.ID)).SetPasswordHash(crypto.BcryptHashMust(req.NewPasswordHash)).SetPasswordChangedAt(time.Now()).Save(ctx); err != nil {
		return nil, errs.Internal(ctx).WithMessage("change current user password failed").Err()
	}
	if a.logger != nil {
		a.logger.Infof("current user password changed: user_id=%d", userID)
	}
	return &emptypb.Empty{}, nil
}

func currentUserETag(userID int, updatedAt time.Time) string {
	payload := strconv.Itoa(userID) + "\n" + updatedAt.UTC().Format(time.RFC3339Nano)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}
