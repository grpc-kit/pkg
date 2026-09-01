package admin

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
)

// GetAuthCallback 处理 OAuth2.0 的回调
func (a *KnownAdminAPI) GetAuthCallback(ctx context.Context, req *adminv1.GetAuthCallbackRequest) (*adminv1.GetAuthCallbackResponse, error) {
	ttl := a.getLoginAccessTokenTTL(ctx)
	result := &adminv1.GetAuthCallbackResponse{
		TokenType: "Bearer",
		ExpiresIn: durationSecondsInt32(ttl),
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 根据不同的 provider_name 选择个性处理方式
	su, err := newSocialUsers(ctx, a.logger, a.config.aesKey, db, req.GetProviderName())
	if err != nil {
		return nil, err
	}
	issuance, err := a.newAccessTokenIssuanceContext("", "", ttl)
	if err != nil {
		return nil, errs.FailedPrecondition(ctx).WithMessage(err.Error())
	}
	su.issuanceContext = issuance

	accessToken, err := su.Exchange(ctx, req.GetCode())
	if err != nil {
		if errors.Is(err, errExternalEmailAlreadyExists) {
			return nil, externalEmailAlreadyExistsPublicError(ctx)
		}
		if errors.Is(err, errExternalPhoneAlreadyExists) {
			return nil, externalPhoneAlreadyExistsPublicError(ctx)
		}
		if errors.Is(err, errExternalVerifiedIdentifiersConflict) {
			return nil, externalVerifiedIdentifiersConflictPublicError(ctx)
		}
		if errors.Is(err, errExternalIdentityAlreadyBound) {
			return nil, externalIdentityAlreadyBoundPublicError(ctx)
		}
		return nil, err
	}

	userID, username, err := extractUserFromAccessToken(accessToken)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to parse callback access token")
	}

	userMFAEnabled, err := hasUserMFAEnabledIdentity(ctx, db, userID)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to query user MFA status")
	}

	authToken, err := a.applyMFAGateAfterPrimaryAuth(ctx, db, userID, username, userMFAEnabled, accessToken, issuance)
	if err != nil {
		return nil, err
	}

	if authToken.GetMfaRequired() {
		result.MfaRequired = true
		result.ChallengeId = authToken.GetChallengeId()
		result.ChallengeType = authToken.GetChallengeType()
		return result, nil
	}
	result.AccessToken = authToken.GetAccessToken()
	if authToken.GetExpiresIn() > 0 {
		result.ExpiresIn = authToken.GetExpiresIn()
	}

	return result, nil
}

func extractUserFromAccessToken(accessToken string) (int, string, error) {
	parser := jwt.NewParser()
	claims := jwt.MapClaims{}
	if _, _, err := parser.ParseUnverified(accessToken, claims); err != nil {
		return 0, "", err
	}

	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return 0, "", fmt.Errorf("subject is empty")
	}
	userID, err := strconv.Atoi(sub)
	if err != nil {
		return 0, "", err
	}

	username, _ := claims["preferred_username"].(string)
	if username == "" {
		// 兼容历史自定义 username claim。
		username, _ = claims["username"].(string)
	}
	return userID, username, nil
}
