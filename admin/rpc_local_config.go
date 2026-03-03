package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"google.golang.org/protobuf/proto"
)

func defaultLocalConfigSnapshot() *adminv1.LocalConfig {
	return &adminv1.LocalConfig{
		Services:    &adminv1.ServicesConfig{Name: "基础服务", Enabled: false},
		Discover:    &adminv1.DiscoverConfig{Name: "服务发现", Enabled: false},
		Security:    &adminv1.SecurityConfig{Name: "认证鉴权", Enabled: false},
		Database:    &adminv1.DatabaseConfig{Name: "关系存储", Enabled: false},
		Cachebox:    &adminv1.CacheboxConfig{Name: "缓存服务", Enabled: false},
		Debugger:    &adminv1.DebuggerConfig{Name: "日志调试", Enabled: false},
		Objstore:    &adminv1.ObjstoreConfig{Name: "对象存储", Enabled: false},
		Frontend:    &adminv1.FrontendConfig{Name: "前端托管", Enabled: false},
		Observables: &adminv1.ObservablesConfig{Name: "可观测性", Enabled: false},
		Cloudevents: &adminv1.CloudEventsConfig{Name: "消息事件", Enabled: false},
		Automations: &adminv1.AutomationsConfig{Name: "流程编排", Enabled: false},
	}
}

func (a *KnownAdminAPI) getLocalConfigSnapshot() *adminv1.LocalConfig {
	if a != nil && a.config != nil && a.config.localConfigSnapshot != nil {
		return proto.Clone(a.config.localConfigSnapshot).(*adminv1.LocalConfig)
	}
	return defaultLocalConfigSnapshot()
}

func (a *KnownAdminAPI) mergeStaticUsers(security *adminv1.SecurityConfig) *adminv1.SecurityConfig {
	if security == nil {
		security = &adminv1.SecurityConfig{Name: "认证鉴权"}
	}
	if security.Authentication == nil {
		security.Authentication = &adminv1.Authentication{}
	}
	if security.Authentication.HttpUsers == nil {
		security.Authentication.HttpUsers = make([]*adminv1.BasicAuth, 0)
	}

	if a == nil || a.config == nil || a.config.staticUsers == nil {
		return security
	}

	exist := make(map[string]struct{}, len(security.Authentication.HttpUsers))
	for _, user := range security.Authentication.HttpUsers {
		if user == nil {
			continue
		}
		exist[user.Username] = struct{}{}
	}

	for _, user := range *a.config.staticUsers {
		if _, ok := exist[user.Username]; ok {
			continue
		}
		userID := user.UserID
		if userID == 0 {
			userID = crypto.Username2UserID(user.Username)
		}

		security.Authentication.HttpUsers = append(security.Authentication.HttpUsers, &adminv1.BasicAuth{
			UserId:       userID,
			Username:     user.Username,
			Password:     "******",
			PasswordHash: "******",
			Groups:       user.Groups,
			Tenant:       user.Tenant,
		})
	}

	return security
}

// GetConfig 获取配置内容
func (a *KnownAdminAPI) GetConfig(ctx context.Context, req *adminv1.GetConfigRequest) (*adminv1.LocalConfig, error) {
	snapshot := a.getLocalConfigSnapshot()
	snapshot.Security = a.mergeStaticUsers(snapshot.Security)
	return snapshot, nil
}

func (a *KnownAdminAPI) GetConfigServices(ctx context.Context, req *adminv1.GetConfigServicesRequest) (*adminv1.ServicesConfig, error) {
	return a.getLocalConfigSnapshot().Services, nil
}

func (a *KnownAdminAPI) GetConfigDiscover(ctx context.Context, req *adminv1.GetConfigDiscoverRequest) (*adminv1.DiscoverConfig, error) {
	return a.getLocalConfigSnapshot().Discover, nil
}

func (a *KnownAdminAPI) GetConfigDatabase(ctx context.Context, req *adminv1.GetConfigDatabaseRequest) (*adminv1.DatabaseConfig, error) {
	return a.getLocalConfigSnapshot().Database, nil
}

func (a *KnownAdminAPI) GetConfigCachebox(ctx context.Context, req *adminv1.GetConfigCacheboxRequest) (*adminv1.CacheboxConfig, error) {
	return a.getLocalConfigSnapshot().Cachebox, nil
}

func (a *KnownAdminAPI) GetConfigDebugger(ctx context.Context, req *adminv1.GetConfigDebuggerRequest) (*adminv1.DebuggerConfig, error) {
	return a.getLocalConfigSnapshot().Debugger, nil
}

func (a *KnownAdminAPI) GetConfigObjstore(ctx context.Context, req *adminv1.GetConfigObjstoreRequest) (*adminv1.ObjstoreConfig, error) {
	return a.getLocalConfigSnapshot().Objstore, nil
}

func (a *KnownAdminAPI) GetConfigFrontend(ctx context.Context, req *adminv1.GetConfigFrontendRequest) (*adminv1.FrontendConfig, error) {
	return a.getLocalConfigSnapshot().Frontend, nil
}

func (a *KnownAdminAPI) GetConfigObservables(ctx context.Context, req *adminv1.GetConfigObservablesRequest) (*adminv1.ObservablesConfig, error) {
	return a.getLocalConfigSnapshot().Observables, nil
}

func (a *KnownAdminAPI) GetConfigCloudEvents(ctx context.Context, req *adminv1.GetConfigCloudEventsRequest) (*adminv1.CloudEventsConfig, error) {
	return a.getLocalConfigSnapshot().Cloudevents, nil
}

func (a *KnownAdminAPI) GetConfigAutomations(ctx context.Context, req *adminv1.GetConfigAutomationsRequest) (*adminv1.AutomationsConfig, error) {
	return a.getLocalConfigSnapshot().Automations, nil
}

// GetConfigSecurity xx
func (a *KnownAdminAPI) GetConfigSecurity(ctx context.Context, req *adminv1.GetConfigSecurityRequest) (*adminv1.SecurityConfig, error) {
	return a.mergeStaticUsers(a.getLocalConfigSnapshot().Security), nil
}
