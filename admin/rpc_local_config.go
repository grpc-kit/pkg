package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
)

// GetConfig 获取配置内容
func (a *KnownAdminAPI) GetConfig(ctx context.Context, req *adminv1.GetConfigRequest) (*adminv1.GetConfigResponse, error) {
	result := &adminv1.GetConfigResponse{}
	return result, nil
}

// GetLocalConfigSecurity xx
func (a *KnownAdminAPI) GetLocalConfigSecurity(ctx context.Context, req *adminv1.GetLocalConfigSecurityRequest) (*adminv1.SecurityConfig, error) {
	result := &adminv1.SecurityConfig{
		Enable: true,
		Authentication: &adminv1.Authentication{
			HttpUsers: make([]*adminv1.BasicAuth, 0),
		},
	}

	if a.config == nil || a.config.staticUsers == nil {
		return result, nil
	}

	for _, user := range *a.config.staticUsers {
		userID := user.UserID
		if userID == 0 {
			userID = crypto.Username2UserID(user.Username)
		}

		result.Authentication.HttpUsers = append(result.Authentication.HttpUsers, &adminv1.BasicAuth{
			UserId:       userID,
			Username:     user.Username,
			Password:     user.PasswordHash,
			PasswordHash: user.PasswordHash,
			Groups:       user.Groups,
			Tenant:       user.Tenant,
		})
	}

	return result, nil
}
