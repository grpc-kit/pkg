package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

func defaultLocalConfigSnapshot() *LocalConfigSnapshot {
	return &LocalConfigSnapshot{
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

func cloneLocalConfigSnapshot(snapshot *LocalConfigSnapshot) *LocalConfigSnapshot {
	if snapshot == nil {
		return defaultLocalConfigSnapshot()
	}

	cloneStruct := func(v *adminv1.ServicesConfig) *adminv1.ServicesConfig {
		if v == nil {
			return nil
		}
		return proto.Clone(v).(*adminv1.ServicesConfig)
	}

	cloned := &LocalConfigSnapshot{
		Services:    cloneStruct(snapshot.Services),
		Discover:    nil,
		Security:    nil,
		Database:    nil,
		Cachebox:    nil,
		Debugger:    nil,
		Objstore:    nil,
		Frontend:    nil,
		Observables: nil,
		Cloudevents: nil,
		Automations: nil,
		Independent: nil,
	}
	if snapshot.Discover != nil {
		cloned.Discover = proto.Clone(snapshot.Discover).(*adminv1.DiscoverConfig)
	}
	if snapshot.Security != nil {
		cloned.Security = proto.Clone(snapshot.Security).(*adminv1.SecurityConfig)
	}
	if snapshot.Database != nil {
		cloned.Database = proto.Clone(snapshot.Database).(*adminv1.DatabaseConfig)
	}
	if snapshot.Cachebox != nil {
		cloned.Cachebox = proto.Clone(snapshot.Cachebox).(*adminv1.CacheboxConfig)
	}
	if snapshot.Debugger != nil {
		cloned.Debugger = proto.Clone(snapshot.Debugger).(*adminv1.DebuggerConfig)
	}
	if snapshot.Objstore != nil {
		cloned.Objstore = proto.Clone(snapshot.Objstore).(*adminv1.ObjstoreConfig)
	}
	if snapshot.Frontend != nil {
		cloned.Frontend = proto.Clone(snapshot.Frontend).(*adminv1.FrontendConfig)
	}
	if snapshot.Observables != nil {
		cloned.Observables = proto.Clone(snapshot.Observables).(*adminv1.ObservablesConfig)
	}
	if snapshot.Cloudevents != nil {
		cloned.Cloudevents = proto.Clone(snapshot.Cloudevents).(*adminv1.CloudEventsConfig)
	}
	if snapshot.Automations != nil {
		cloned.Automations = proto.Clone(snapshot.Automations).(*adminv1.AutomationsConfig)
	}
	if snapshot.Independent != nil {
		cloned.Independent = proto.Clone(snapshot.Independent).(*structpb.Struct)
	}

	return cloned
}

func (a *KnownAdminAPI) getLocalConfigSnapshot() *LocalConfigSnapshot {
	if a != nil && a.config != nil && a.config.localConfigSnapshot != nil {
		return cloneLocalConfigSnapshot(a.config.localConfigSnapshot)
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
func (a *KnownAdminAPI) ListLocalConfigs(ctx context.Context, req *adminv1.ListLocalConfigsRequest) (*adminv1.ListLocalConfigsResponse, error) {
	snapshot := a.getLocalConfigSnapshot()

	entries := []*adminv1.LocalConfigEntry{
		{Name: "services", Enabled: snapshot.Services != nil && snapshot.Services.Enabled},
		{Name: "discover", Enabled: snapshot.Discover != nil && snapshot.Discover.Enabled},
		{Name: "security", Enabled: snapshot.Security != nil && snapshot.Security.Enabled},
		{Name: "database", Enabled: snapshot.Database != nil && snapshot.Database.Enabled},
		{Name: "cachebox", Enabled: snapshot.Cachebox != nil && snapshot.Cachebox.Enabled},
		{Name: "debugger", Enabled: snapshot.Debugger != nil && snapshot.Debugger.Enabled},
		{Name: "objstore", Enabled: snapshot.Objstore != nil && snapshot.Objstore.Enabled},
		{Name: "frontend", Enabled: snapshot.Frontend != nil && snapshot.Frontend.Enabled},
		{Name: "observables", Enabled: snapshot.Observables != nil && snapshot.Observables.Enabled},
		{Name: "cloudevents", Enabled: snapshot.Cloudevents != nil && snapshot.Cloudevents.Enabled},
		{Name: "automations", Enabled: snapshot.Automations != nil && snapshot.Automations.Enabled},
	}

	return &adminv1.ListLocalConfigsResponse{Configs: entries}, nil
}

func (a *KnownAdminAPI) GetLocalConfigs(ctx context.Context, req *adminv1.GetLocalConfigsRequest) (*adminv1.LocalConfigs, error) {
	if req == nil || req.Name == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("name is required")
	}

	snapshot := a.getLocalConfigSnapshot()

	switch req.Name {
	case "services":
		return &adminv1.LocalConfigs{Config: &adminv1.LocalConfigs_Services{Services: snapshot.Services}}, nil
	case "discover":
		return &adminv1.LocalConfigs{Config: &adminv1.LocalConfigs_Discover{Discover: snapshot.Discover}}, nil
	case "security":
		return &adminv1.LocalConfigs{Config: &adminv1.LocalConfigs_Security{Security: a.mergeStaticUsers(snapshot.Security)}}, nil
	case "database":
		return &adminv1.LocalConfigs{Config: &adminv1.LocalConfigs_Database{Database: snapshot.Database}}, nil
	case "cachebox":
		return &adminv1.LocalConfigs{Config: &adminv1.LocalConfigs_Cachebox{Cachebox: snapshot.Cachebox}}, nil
	case "debugger":
		return &adminv1.LocalConfigs{Config: &adminv1.LocalConfigs_Debugger{Debugger: snapshot.Debugger}}, nil
	case "objstore":
		return &adminv1.LocalConfigs{Config: &adminv1.LocalConfigs_Objstore{Objstore: snapshot.Objstore}}, nil
	case "frontend":
		return &adminv1.LocalConfigs{Config: &adminv1.LocalConfigs_Frontend{Frontend: snapshot.Frontend}}, nil
	case "observables":
		return &adminv1.LocalConfigs{Config: &adminv1.LocalConfigs_Observables{Observables: snapshot.Observables}}, nil
	case "cloudevents":
		return &adminv1.LocalConfigs{Config: &adminv1.LocalConfigs_Cloudevents{Cloudevents: snapshot.Cloudevents}}, nil
	case "automations":
		return &adminv1.LocalConfigs{Config: &adminv1.LocalConfigs_Automations{Automations: snapshot.Automations}}, nil
	case "independent":
		return &adminv1.LocalConfigs{Config: &adminv1.LocalConfigs_Independent{Independent: snapshot.Independent}}, nil
	default:
		return nil, errs.InvalidArgument(ctx).WithMessage("unsupported local config name")
	}
}
