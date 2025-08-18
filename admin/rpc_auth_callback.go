package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
)

// GetAuthCallback 处理 OAuth2.0 的回调
func (a *KnownAdminAPI) GetAuthCallback(ctx context.Context, req *adminv1.GetAuthCallbackRequest) (*adminv1.GetAuthCallbackResponse, error) {
	result := &adminv1.GetAuthCallbackResponse{
		TokenType: "Bearer",
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

	result.AccessToken = accessToken

	return result, nil
}
