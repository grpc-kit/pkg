package admin

import (
	"context"
	"testing"
)

func TestIdentityAutoLinkSettingRegistry(t *testing.T) {
	spec, ok := lookupGlobalSettingSpec(globalSettingsCategorySecurity, globalSettingKeyIdentityAutoLink)
	if !ok {
		t.Fatal("identity.auto_link is not registered")
	}
	if spec.ValueType != globalSettingValueTypeBool || spec.DefaultValue != "true" || !spec.Protected {
		t.Fatalf("unexpected setting spec: %+v", spec)
	}
	for _, value := range []string{"true", "false"} {
		if err := validateGlobalSettingValue(globalSettingKeyIdentityAutoLink, value, spec); err != nil {
			t.Fatalf("validate %q: %v", value, err)
		}
	}
	for _, value := range []string{"", "1", `{"enabled":true}`} {
		if err := validateGlobalSettingValue(globalSettingKeyIdentityAutoLink, value, spec); err == nil {
			t.Fatalf("validate %q error = nil", value)
		}
	}
}

func TestIdentityAutoLinkSettingDefaultWithoutDatabase(t *testing.T) {
	enabled, found, err := newGlobalSettingsReader(nil, nil).GetBool(
		context.Background(),
		globalSettingsCategorySecurity,
		globalSettingKeyIdentityAutoLink,
	)
	if err != nil || found || !enabled {
		t.Fatalf("GetBool = (%v, %v, %v), want true/not-found/no-error", enabled, found, err)
	}
}
