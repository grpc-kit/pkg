package adminv1

import (
	"encoding/json"
	"testing"
)

func TestAssetsIncludesAdminSwaggerDocument(t *testing.T) {
	content, err := Assets.ReadFile("openapi/admin.swagger.json")
	if err != nil {
		t.Fatalf("read embedded admin swagger: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("unmarshal embedded admin swagger: %v", err)
	}

	if _, ok := document["swagger"]; !ok {
		if _, ok := document["openapi"]; !ok {
			t.Fatalf("embedded admin swagger missing swagger/openapi version field")
		}
	}
	if _, ok := document["paths"]; !ok {
		t.Fatalf("embedded admin swagger missing paths field")
	}
}
