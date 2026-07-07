package admin

import (
	"context"
	"fmt"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
	"github.com/grpc-kit/pkg/lion/useridentities"
)

const (
	mfaChallengeTypeTotpVerify = "TOTP_VERIFY"
	mfaChallengeTypeTotpSetup  = "TOTP_SETUP"
)

// getLocalMFAPolicy 获取 LOCAL provider 的全局 MFA 策略及其 provider_id
func (a *KnownAdminAPI) getLocalMFAPolicy(ctx context.Context, db *lion.Client) (enforce bool, localProviderID int, err error) {
	row, err := db.AuthProviders.Query().
		Select(
			authproviders.FieldID,
			authproviders.FieldProviderStatus,
			authproviders.FieldConfig,
		).
		Where(
			authproviders.CodeEQ("local"),
			authproviders.ProviderTypeEQ(int(adminv1.AuthProvider_LOCAL.Number())),
			authproviders.DeletedAtIsNil(),
		).
		First(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return false, 0, nil
		}
		return false, 0, err
	}

	// provider 不可用时，不启用全局强制
	if row.ProviderStatus != int(adminv1.AuthProvider_ACTIVE.Number()) {
		return false, row.ID, nil
	}

	settingsReader := newGlobalSettingsReader(a.logger, db)
	settingEnforce, _, err := settingsReader.GetBool(ctx, globalSettingsCategorySecurity, globalSettingKeyLoginEnforceMFA)
	if err != nil {
		return false, row.ID, err
	}
	return settingEnforce, row.ID, nil
}

// ensureLocalIdentity 确保用户存在 local identity（用于统一执行 LOCAL MFA 门禁）
func (a *KnownAdminAPI) ensureLocalIdentity(ctx context.Context, db *lion.Client, userID int, username string, localProviderID int) error {
	if localProviderID == 0 || userID == 0 {
		return nil
	}

	_, err := db.UserIdentities.Query().
		Select(useridentities.FieldID).
		Where(
			useridentities.UserIDEQ(userID),
			useridentities.ProviderIDEQ(localProviderID),
		).
		First(ctx)
	if err == nil {
		return nil
	}
	if !lion.IsNotFound(err) {
		return err
	}

	providerUserID := username
	if providerUserID == "" {
		providerUserID = fmt.Sprintf("local:%d", userID)
	}

	_, err = db.UserIdentities.Create().
		SetUserID(userID).
		SetProviderID(localProviderID).
		SetProviderUserID(providerUserID).
		Save(ctx)
	return err
}

func (a *KnownAdminAPI) createMFALoginChallenge(ctx context.Context, challengeType mfaChallengeType, userID int, username string, responseType string) (*adminv1.AuthToken, error) {
	challenge, err := a.mfaChallenges.CreateWithTTL(a.getMFAChallengeTTL(ctx), challengeType, userID, username)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to create MFA challenge")
	}
	return &adminv1.AuthToken{
		MfaRequired:   true,
		ChallengeId:   challenge.ChallengeID,
		ChallengeType: responseType,
	}, nil
}

// applyMFAGateAfterPrimaryAuth 统一的一阶认证后 MFA 门禁
func (a *KnownAdminAPI) applyMFAGateAfterPrimaryAuth(
	ctx context.Context,
	db *lion.Client,
	userID int,
	username string,
	providerMFAEnabled bool,
	fallbackToken string,
) (*adminv1.AuthToken, error) {
	enforce, localProviderID, err := a.getLocalMFAPolicy(ctx, db)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to query local MFA policy")
	}

	if enforce {
		if err := a.ensureLocalIdentity(ctx, db, userID, username, localProviderID); err != nil {
			return nil, errs.Internal(ctx).WithMessage("failed to ensure local identity for MFA policy")
		}

		localIdentity, err := db.UserIdentities.Query().
			Select(
				useridentities.FieldMfaEnabled,
			).
			Where(
				useridentities.UserIDEQ(userID),
				useridentities.ProviderIDEQ(localProviderID),
			).
			First(ctx)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage("failed to query local identity for MFA")
		}

		if localIdentity.MfaEnabled {
			return a.createMFALoginChallenge(ctx, mfaChallengeTypeLoginVerify, userID, username, mfaChallengeTypeTotpVerify)
		}
		return a.createMFALoginChallenge(ctx, mfaChallengeTypeLoginSetup, userID, username, mfaChallengeTypeTotpSetup)
	}

	// 非强制策略，保留原有“用户已开启 MFA 则验证”的行为
	if providerMFAEnabled {
		return a.createMFALoginChallenge(ctx, mfaChallengeTypeLoginVerify, userID, username, mfaChallengeTypeTotpVerify)
	}

	accessToken := fallbackToken
	if accessToken == "" {
		accessToken, err = a.issueTokenForUser(ctx, db, userID)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage("failed to issue access token")
		}
	}

	return &adminv1.AuthToken{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   durationSecondsInt32(a.getLoginAccessTokenTTL(ctx)),
	}, nil
}
