package cfg

import "testing"

func TestToStructMasksIndependentSecretsRecursively(t *testing.T) {
	snapshot := toStruct(map[string]any{
		"database": map[string]any{
			"password": "plain-password",
			"username": "admin",
		},
		"clients": []any{
			map[string]any{"client_secret": "plain-secret", "name": "worker"},
		},
		"tls": map[string]any{
			"key_file":   "/run/tls/client.key",
			"token_file": "/run/secrets/token",
		},
		"empty_secret": "",
	})
	if snapshot == nil {
		t.Fatal("expected independent snapshot")
	}
	value := snapshot.AsMap()
	database := value["database"].(map[string]any)
	if database["password"] != maskedValue {
		t.Fatalf("password was not masked: %#v", database["password"])
	}
	if database["username"] != "admin" {
		t.Fatalf("non-sensitive value changed: %#v", database["username"])
	}
	clients := value["clients"].([]any)
	client := clients[0].(map[string]any)
	if client["client_secret"] != maskedValue {
		t.Fatalf("nested client_secret was not masked: %#v", client["client_secret"])
	}
	tls := value["tls"].(map[string]any)
	if tls["key_file"] != "/run/tls/client.key" || tls["token_file"] != "/run/secrets/token" {
		t.Fatalf("file paths must remain visible: %#v", tls)
	}
	if value["empty_secret"] != "" {
		t.Fatalf("empty secret should stay empty: %#v", value["empty_secret"])
	}
}

func TestSecuritySnapshotMasksOPAExternalConfig(t *testing.T) {
	enabled := true
	config := &LocalConfig{
		Security: &SecurityConfig{
			Enable: true,
			Authorization: &Authorization{
				OPAExternal: OPAExternal{
					Enabled: &enabled,
					Config:  "services:\n  auth:\n    bearer: plain-secret",
				},
			},
		},
	}
	snapshot := config.toAdminSecurityConfig()
	if snapshot.GetAuthorization().GetOpaExternal().GetConfig() != maskedValue {
		t.Fatalf("OPA external config must be fully masked")
	}
}
