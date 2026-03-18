package admin

import (
	"context"
	"fmt"
	"strconv"

	"github.com/golang-jwt/jwt/v4"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
)

// GetAuthCallback 处理 OAuth2.0 的回调
func (a *KnownAdminAPI) GetAuthCallback(ctx context.Context, req *adminv1.GetAuthCallbackRequest) (*adminv1.GetAuthCallbackResponse, error) {
	result := &adminv1.GetAuthCallbackResponse{
		TokenType: "Bearer",
		ExpiresIn: 24 * 60 * 60,
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

	accessToken, err := su.Exchange(ctx, req.GetCode())
	if err != nil {
		return nil, err
	}

	userID, username, err := extractUserFromAccessToken(accessToken)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to parse callback access token")
	}

	authToken, err := a.applyMFAGateAfterPrimaryAuth(ctx, db, userID, username, false, accessToken)
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

	username, _ := claims["username"].(string)
	return userID, username, nil
}
