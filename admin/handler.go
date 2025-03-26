package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
)

func (a *AdminAPI) GetConfig(ctx context.Context, req *adminv1.GetConfigRequest) (*adminv1.GetConfigResponse, error) {
	result := &adminv1.GetConfigResponse{}
	return result, nil
}

func (a *AdminAPI) AuthLogin(ctx context.Context, req *adminv1.AuthLoginRequest) (*adminv1.AuthLoginResponse, error) {
	result := &adminv1.AuthLoginResponse{}
	return result, nil
}
