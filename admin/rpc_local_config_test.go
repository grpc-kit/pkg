package admin

import (
	"context"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestListLocalConfigs_OmitsIndependent(t *testing.T) {
	api := New(WithLocalConfigSnapshot(&LocalConfigSnapshot{
		Services:    &adminv1.ServicesConfig{Name: "services", Enabled: true},
		Discover:    &adminv1.DiscoverConfig{Name: "discover", Enabled: false},
		Security:    &adminv1.SecurityConfig{Name: "security", Enabled: true},
		Database:    &adminv1.DatabaseConfig{Name: "database", Enabled: true},
		Cachebox:    &adminv1.CacheboxConfig{Name: "cachebox", Enabled: false},
		Debugger:    &adminv1.DebuggerConfig{Name: "debugger", Enabled: false},
		Objstore:    &adminv1.ObjstoreConfig{Name: "objstore", Enabled: true},
		Frontend:    &adminv1.FrontendConfig{Name: "frontend", Enabled: true},
		Observables: &adminv1.ObservablesConfig{Name: "observables", Enabled: true},
		Cloudevents: &adminv1.CloudEventsConfig{Name: "cloudevents", Enabled: false},
		Automations: &adminv1.AutomationsConfig{Name: "automations", Enabled: true},
		Independent: &structpb.Struct{},
	}))

	resp, err := api.ListLocalConfigs(context.Background(), &adminv1.ListLocalConfigsRequest{})
	if err != nil {
		t.Fatalf("ListLocalConfigs returned error: %v", err)
	}
	if len(resp.GetConfigs()) != 11 {
		t.Fatalf("expected 11 local config entries, got %d", len(resp.GetConfigs()))
	}
	for _, entry := range resp.GetConfigs() {
		if entry.GetName() == "independent" {
			t.Fatalf("list response should not include independent entry")
		}
	}
}

func TestGetLocalConfigs_SecurityIncludesStaticUsers(t *testing.T) {
	users := StaticUsers{
		&StaticUser{Username: "new-user", Groups: []string{"ops"}, Tenant: "default"},
	}
	api := New(
		WithStaticUsers(&users),
		WithLocalConfigSnapshot(&LocalConfigSnapshot{
			Security: &adminv1.SecurityConfig{
				Name:    "security",
				Enabled: true,
				Authentication: &adminv1.Authentication{
					HttpUsers: []*adminv1.BasicAuth{
						{Username: "existing", Groups: []string{"root"}},
					},
				},
			},
		}),
	)

	resp, err := api.GetLocalConfigs(context.Background(), &adminv1.GetLocalConfigsRequest{Name: "security"})
	if err != nil {
		t.Fatalf("GetLocalConfigs returned error: %v", err)
	}
	security := resp.GetSecurity()
	if security == nil || security.Authentication == nil {
		t.Fatalf("expected security authentication payload")
	}
	if len(security.Authentication.HttpUsers) != 2 {
		t.Fatalf("expected merged users length=2, got %d", len(security.Authentication.HttpUsers))
	}
}

func TestGetLocalConfigs_InvalidName(t *testing.T) {
	api := New()
	_, err := api.GetLocalConfigs(context.Background(), &adminv1.GetLocalConfigsRequest{Name: "unknown"})
	if err == nil {
		t.Fatalf("expected error for unknown local config name")
	}
}

// Tests for individual oneof branches
func TestGetLocalConfigs_Services(t *testing.T) {
	expectedConfig := &adminv1.ServicesConfig{
		Name:    "services",
		Enabled: true,
	}
	api := New(WithLocalConfigSnapshot(&LocalConfigSnapshot{
		Services: expectedConfig,
	}))

	resp, err := api.GetLocalConfigs(context.Background(), &adminv1.GetLocalConfigsRequest{Name: "services"})
	if err != nil {
		t.Fatalf("GetLocalConfigs returned error: %v", err)
	}

	config := resp.GetServices()
	if config == nil {
		t.Fatalf("expected services config, got nil")
	}
	if config.Name != "services" || !config.Enabled {
		t.Fatalf("services config mismatch")
	}
	// Verify other branches are nil
	if resp.GetDiscover() != nil || resp.GetSecurity() != nil || resp.GetDatabase() != nil {
		t.Fatalf("expected only services branch to be set")
	}
}

func TestGetLocalConfigs_Discover(t *testing.T) {
	expectedConfig := &adminv1.DiscoverConfig{
		Name:    "discover",
		Enabled: true,
	}
	api := New(WithLocalConfigSnapshot(&LocalConfigSnapshot{
		Discover: expectedConfig,
	}))

	resp, err := api.GetLocalConfigs(context.Background(), &adminv1.GetLocalConfigsRequest{Name: "discover"})
	if err != nil {
		t.Fatalf("GetLocalConfigs returned error: %v", err)
	}

	config := resp.GetDiscover()
	if config == nil {
		t.Fatalf("expected discover config, got nil")
	}
	if config.Name != "discover" {
		t.Fatalf("discover config mismatch")
	}
	// Verify other branches are nil
	if resp.GetServices() != nil || resp.GetSecurity() != nil {
		t.Fatalf("expected only discover branch to be set")
	}
}

func TestGetLocalConfigs_Database(t *testing.T) {
	expectedConfig := &adminv1.DatabaseConfig{
		Name:    "database",
		Enabled: true,
	}
	api := New(WithLocalConfigSnapshot(&LocalConfigSnapshot{
		Database: expectedConfig,
	}))

	resp, err := api.GetLocalConfigs(context.Background(), &adminv1.GetLocalConfigsRequest{Name: "database"})
	if err != nil {
		t.Fatalf("GetLocalConfigs returned error: %v", err)
	}

	config := resp.GetDatabase()
	if config == nil {
		t.Fatalf("expected database config, got nil")
	}
	if config.Name != "database" {
		t.Fatalf("database config mismatch")
	}
	// Verify other branches are nil
	if resp.GetServices() != nil || resp.GetDiscover() != nil {
		t.Fatalf("expected only database branch to be set")
	}
}

func TestGetLocalConfigs_Cachebox(t *testing.T) {
	expectedConfig := &adminv1.CacheboxConfig{
		Name:    "cachebox",
		Enabled: false,
	}
	api := New(WithLocalConfigSnapshot(&LocalConfigSnapshot{
		Cachebox: expectedConfig,
	}))

	resp, err := api.GetLocalConfigs(context.Background(), &adminv1.GetLocalConfigsRequest{Name: "cachebox"})
	if err != nil {
		t.Fatalf("GetLocalConfigs returned error: %v", err)
	}

	config := resp.GetCachebox()
	if config == nil {
		t.Fatalf("expected cachebox config, got nil")
	}
	if config.Name != "cachebox" || config.Enabled {
		t.Fatalf("cachebox config mismatch")
	}
}

func TestGetLocalConfigs_Debugger(t *testing.T) {
	expectedConfig := &adminv1.DebuggerConfig{
		Name:    "debugger",
		Enabled: true,
	}
	api := New(WithLocalConfigSnapshot(&LocalConfigSnapshot{
		Debugger: expectedConfig,
	}))

	resp, err := api.GetLocalConfigs(context.Background(), &adminv1.GetLocalConfigsRequest{Name: "debugger"})
	if err != nil {
		t.Fatalf("GetLocalConfigs returned error: %v", err)
	}

	config := resp.GetDebugger()
	if config == nil {
		t.Fatalf("expected debugger config, got nil")
	}
	if config.Name != "debugger" {
		t.Fatalf("debugger config mismatch")
	}
}

func TestGetLocalConfigs_Objstore(t *testing.T) {
	expectedConfig := &adminv1.ObjstoreConfig{
		Name:    "objstore",
		Enabled: true,
	}
	api := New(WithLocalConfigSnapshot(&LocalConfigSnapshot{
		Objstore: expectedConfig,
	}))

	resp, err := api.GetLocalConfigs(context.Background(), &adminv1.GetLocalConfigsRequest{Name: "objstore"})
	if err != nil {
		t.Fatalf("GetLocalConfigs returned error: %v", err)
	}

	config := resp.GetObjstore()
	if config == nil {
		t.Fatalf("expected objstore config, got nil")
	}
	if config.Name != "objstore" {
		t.Fatalf("objstore config mismatch")
	}
}

func TestGetLocalConfigs_Frontend(t *testing.T) {
	expectedConfig := &adminv1.FrontendConfig{
		Name:    "frontend",
		Enabled: true,
	}
	api := New(WithLocalConfigSnapshot(&LocalConfigSnapshot{
		Frontend: expectedConfig,
	}))

	resp, err := api.GetLocalConfigs(context.Background(), &adminv1.GetLocalConfigsRequest{Name: "frontend"})
	if err != nil {
		t.Fatalf("GetLocalConfigs returned error: %v", err)
	}

	config := resp.GetFrontend()
	if config == nil {
		t.Fatalf("expected frontend config, got nil")
	}
	if config.Name != "frontend" {
		t.Fatalf("frontend config mismatch")
	}
}

func TestGetLocalConfigs_Observables(t *testing.T) {
	expectedConfig := &adminv1.ObservablesConfig{
		Name:    "observables",
		Enabled: true,
	}
	api := New(WithLocalConfigSnapshot(&LocalConfigSnapshot{
		Observables: expectedConfig,
	}))

	resp, err := api.GetLocalConfigs(context.Background(), &adminv1.GetLocalConfigsRequest{Name: "observables"})
	if err != nil {
		t.Fatalf("GetLocalConfigs returned error: %v", err)
	}

	config := resp.GetObservables()
	if config == nil {
		t.Fatalf("expected observables config, got nil")
	}
	if config.Name != "observables" {
		t.Fatalf("observables config mismatch")
	}
}

func TestGetLocalConfigs_Cloudevents(t *testing.T) {
	expectedConfig := &adminv1.CloudEventsConfig{
		Name:    "cloudevents",
		Enabled: false,
	}
	api := New(WithLocalConfigSnapshot(&LocalConfigSnapshot{
		Cloudevents: expectedConfig,
	}))

	resp, err := api.GetLocalConfigs(context.Background(), &adminv1.GetLocalConfigsRequest{Name: "cloudevents"})
	if err != nil {
		t.Fatalf("GetLocalConfigs returned error: %v", err)
	}

	config := resp.GetCloudevents()
	if config == nil {
		t.Fatalf("expected cloudevents config, got nil")
	}
	if config.Name != "cloudevents" || config.Enabled {
		t.Fatalf("cloudevents config mismatch")
	}
}

func TestGetLocalConfigs_Automations(t *testing.T) {
	expectedConfig := &adminv1.AutomationsConfig{
		Name:    "automations",
		Enabled: true,
	}
	api := New(WithLocalConfigSnapshot(&LocalConfigSnapshot{
		Automations: expectedConfig,
	}))

	resp, err := api.GetLocalConfigs(context.Background(), &adminv1.GetLocalConfigsRequest{Name: "automations"})
	if err != nil {
		t.Fatalf("GetLocalConfigs returned error: %v", err)
	}

	config := resp.GetAutomations()
	if config == nil {
		t.Fatalf("expected automations config, got nil")
	}
	if config.Name != "automations" {
		t.Fatalf("automations config mismatch")
	}
}

func TestGetLocalConfigs_Independent(t *testing.T) {
	expectedStruct, _ := structpb.NewStruct(map[string]interface{}{
		"key1": "value1",
		"key2": 42.0,
	})
	api := New(WithLocalConfigSnapshot(&LocalConfigSnapshot{
		Independent: expectedStruct,
	}))

	resp, err := api.GetLocalConfigs(context.Background(), &adminv1.GetLocalConfigsRequest{Name: "independent"})
	if err != nil {
		t.Fatalf("GetLocalConfigs returned error: %v", err)
	}

	config := resp.GetIndependent()
	if config == nil {
		t.Fatalf("expected independent config, got nil")
	}
	if len(config.Fields) != 2 {
		t.Fatalf("expected independent struct with 2 fields, got %d", len(config.Fields))
	}
	// Verify other branches are nil
	if resp.GetServices() != nil || resp.GetDiscover() != nil {
		t.Fatalf("expected only independent branch to be set")
	}
}
