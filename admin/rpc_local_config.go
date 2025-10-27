package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
)

// GetConfig 获取配置内容
func (a *KnownAdminAPI) GetConfig(ctx context.Context, req *adminv1.GetConfigRequest) (*adminv1.LocalConfig, error) {
	result := &adminv1.LocalConfig{
		Services:    &adminv1.ServicesConfig{Name: "基础服务", Enabled: false},
		Discover:    &adminv1.DiscoverConfig{Name: "服务发现", Enabled: false},
		Security:    &adminv1.SecurityConfig{Name: "认证鉴权", Enabled: true},
		Database:    &adminv1.DatabaseConfig{Name: "关系存储", Enabled: false},
		Cachebox:    &adminv1.CacheboxConfig{Name: "缓存服务", Enabled: false},
		Debugger:    &adminv1.DebuggerConfig{Name: "日志调试", Enabled: false},
		Objstore:    &adminv1.ObjstoreConfig{Name: "对象存储", Enabled: false},
		Frontend:    &adminv1.FrontendConfig{Name: "前端托管", Enabled: false},
		Observables: &adminv1.ObservablesConfig{Name: "可观测性", Enabled: false},
		Cloudevents: &adminv1.CloudEventsConfig{Name: "消息事件", Enabled: false},
		Automations: &adminv1.AutomationsConfig{Name: "流程编排", Enabled: false},
	}

	return result, nil
}

// GetConfigSecurity xx
func (a *KnownAdminAPI) GetConfigSecurity(ctx context.Context, req *adminv1.GetConfigSecurityRequest) (*adminv1.SecurityConfig, error) {
	result := &adminv1.SecurityConfig{
		Enabled: true,
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
