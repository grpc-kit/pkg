package admin

import (
	"context"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func TestNormalizeGlobalSettingValueSupportsAllTypes(t *testing.T) {
	tests := []struct {
		name      string
		valueType globalSettingValueType
		input     string
		want      string
	}{
		{name: "bool", valueType: globalSettingValueTypeBool, input: " true ", want: "true"},
		{name: "int", valueType: globalSettingValueTypeInt, input: "0012", want: "12"},
		{name: "float", valueType: globalSettingValueTypeFloat, input: "1.2500", want: "1.25"},
		{name: "duration", valueType: globalSettingValueTypeDuration, input: "60s", want: "1m0s"},
		{name: "string", valueType: globalSettingValueTypeString, input: "  keep me  ", want: "  keep me  "},
		{name: "string array", valueType: globalSettingValueTypeStringArray, input: `["a", "b"]`, want: `["a","b"]`},
		{name: "json", valueType: globalSettingValueTypeJSON, input: `{ "enabled": true }`, want: `{"enabled":true}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeGlobalSettingValue(context.Background(), "custom.value", tt.input, globalSettingSpec{ValueType: tt.valueType})
			if err != nil {
				t.Fatalf("normalizeGlobalSettingValue returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalized value = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeGlobalSettingValueRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		valueType globalSettingValueType
		value     string
	}{
		{valueType: globalSettingValueTypeBool, value: "yes"},
		{valueType: globalSettingValueTypeInt, value: "1.2"},
		{valueType: globalSettingValueTypeFloat, value: "NaN"},
		{valueType: globalSettingValueTypeDuration, value: "tomorrow"},
		{valueType: globalSettingValueTypeStringArray, value: `["ok", 2]`},
		{valueType: globalSettingValueTypeJSON, value: `{"a":1} trailing`},
	}
	for _, tt := range tests {
		if _, err := normalizeGlobalSettingValue(context.Background(), "custom.value", tt.value, globalSettingSpec{ValueType: tt.valueType}); err == nil {
			t.Fatalf("expected %s value %q to be rejected", tt.valueType, tt.value)
		}
	}
}

func TestValidateGlobalSettingKeyBlocksSecretLikeNames(t *testing.T) {
	for _, key := range []string{"database.password", "oauth.client_secret", "service.api-key", "auth.bearer_token"} {
		if err := validateGlobalSettingKey(context.Background(), key); err == nil {
			t.Fatalf("expected secret-like key %q to be rejected", key)
		}
	}
	for _, key := range []string{"feature.enabled", "login.token_ttl", "tls.key_file"} {
		if err := validateGlobalSettingKey(context.Background(), key); err != nil {
			t.Fatalf("expected key %q to be accepted: %v", key, err)
		}
	}
}

func TestGlobalSettingUpdateMaskCompatibility(t *testing.T) {
	value, description, err := globalSettingUpdateFields(context.Background(), &adminv1.UpdateGlobalSetting{})
	if err != nil || !value || description {
		t.Fatalf("empty mask should update value only: value=%v description=%v err=%v", value, description, err)
	}
	value, description, err = globalSettingUpdateFields(context.Background(), &adminv1.UpdateGlobalSetting{
		UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"setting_value", "description"}},
	})
	if err != nil || !value || !description {
		t.Fatalf("explicit mask not applied: value=%v description=%v err=%v", value, description, err)
	}
}

func TestConfigRPCsRequireSuperadmin(t *testing.T) {
	api := New()
	assertDenied := func(name string, err error) {
		t.Helper()
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s code = %s, want PermissionDenied (err=%v)", name, status.Code(err), err)
		}
	}
	for _, ctx := range []context.Context{
		context.Background(),
		rpc.ContextWithRoles(context.Background(), []string{"viewer"}),
	} {
		_, err := api.ListLocalConfigs(ctx, &adminv1.ListLocalConfigsRequest{})
		assertDenied("ListLocalConfigs", err)
		_, err = api.GetLocalConfigs(ctx, &adminv1.GetLocalConfigsRequest{Name: "services"})
		assertDenied("GetLocalConfigs", err)
		_, err = api.ListGlobalSettings(ctx, &adminv1.ListGlobalSettingsRequest{})
		assertDenied("ListGlobalSettings", err)
		_, err = api.GetGlobalSettings(ctx, &adminv1.GetGlobalSettingsRequest{Category: "security"})
		assertDenied("GetGlobalSettings", err)
		_, err = api.CreateGlobalSetting(ctx, &adminv1.CreateGlobalSettingRequest{})
		assertDenied("CreateGlobalSetting", err)
		_, err = api.UpdateGlobalSettings(ctx, &adminv1.UpdateGlobalSettingsRequest{})
		assertDenied("UpdateGlobalSettings", err)
		_, err = api.DeleteGlobalSetting(ctx, &adminv1.DeleteGlobalSettingRequest{})
		assertDenied("DeleteGlobalSetting", err)
	}
}

func TestGlobalSettingsCategoriesAndProtectedNormalization(t *testing.T) {
	if len(globalSettingsCategories) != 13 {
		t.Fatalf("category count = %d, want 13", len(globalSettingsCategories))
	}
	seen := make(map[string]struct{}, len(globalSettingsCategories))
	for _, category := range globalSettingsCategories {
		if !isGlobalSettingsCategory(category) {
			t.Fatalf("category %q is not recognized", category)
		}
		if _, exists := seen[category]; exists {
			t.Fatalf("duplicate category %q", category)
		}
		seen[category] = struct{}{}
	}

	row := &lion.GlobalSettings{Category: "security", SettingKey: "custom.flag", Protected: true}
	if toProtoGlobalSetting(row, false).GetProtected() {
		t.Fatal("custom row must be normalized to protected=false")
	}
	row.Protected = false
	if !toProtoGlobalSetting(row, true).GetProtected() {
		t.Fatal("registry row must be normalized to protected=true")
	}
}
