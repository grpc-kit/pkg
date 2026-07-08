package adminv1

import (
	"encoding/json"
	"fmt"
	"strings"
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

func TestAssetsAdminSwaggerDoesNotContainDotPrefixedRefs(t *testing.T) {
	content, err := Assets.ReadFile("openapi/admin.swagger.json")
	if err != nil {
		t.Fatalf("read embedded admin swagger: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("unmarshal embedded admin swagger: %v", err)
	}

	assertNoDotPrefixedRefs(t, "$", document)
}

func TestAssetsAdminSwaggerIncludesGlobalErrorResponseSchema(t *testing.T) {
	content, err := Assets.ReadFile("openapi/admin.swagger.json")
	if err != nil {
		t.Fatalf("read embedded admin swagger: %v", err)
	}

	var document map[string]any
	if err := json.Unmarshal(content, &document); err != nil {
		t.Fatalf("unmarshal embedded admin swagger: %v", err)
	}

	definitions, ok := document["definitions"].(map[string]any)
	if !ok {
		t.Fatalf("embedded admin swagger missing definitions object")
	}
	if _, ok := definitions["v1ErrorResponse"]; !ok {
		t.Fatalf("embedded admin swagger missing v1ErrorResponse definition")
	}

	paths, ok := document["paths"].(map[string]any)
	if !ok {
		t.Fatalf("embedded admin swagger missing paths object")
	}

	for pathKey, pathValue := range paths {
		operations, ok := pathValue.(map[string]any)
		if !ok {
			t.Fatalf("swagger path %s is not an object: %T", pathKey, pathValue)
		}

		for methodKey, methodValue := range operations {
			operation, ok := methodValue.(map[string]any)
			if !ok {
				t.Fatalf("swagger operation %s %s is not an object: %T", methodKey, pathKey, methodValue)
			}

			responses, ok := operation["responses"].(map[string]any)
			if !ok {
				t.Fatalf("swagger operation %s %s missing responses object", methodKey, pathKey)
			}

			assertResponseRef(t, pathKey, methodKey, responses, "4xx")
			assertResponseRef(t, pathKey, methodKey, responses, "5xx")
		}
	}
}

func assertNoDotPrefixedRefs(t *testing.T, path string, value any) {
	t.Helper()

	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := fmt.Sprintf("%s.%s", path, key)
			if key == "$ref" {
				refValue, ok := child.(string)
				if !ok {
					t.Fatalf("swagger ref at %s is not a string: %T", childPath, child)
				}
				if strings.HasPrefix(refValue, ".") {
					t.Fatalf("swagger contains invalid dot-prefixed ref at %s: %s", childPath, refValue)
				}
			}
			assertNoDotPrefixedRefs(t, childPath, child)
		}
	case []any:
		for index, child := range typed {
			assertNoDotPrefixedRefs(t, fmt.Sprintf("%s[%d]", path, index), child)
		}
	}
}

func assertResponseRef(t *testing.T, pathKey, methodKey string, responses map[string]any, statusCode string) {
	t.Helper()

	responseValue, ok := responses[statusCode]
	if !ok {
		t.Fatalf("swagger operation %s %s missing %s response", methodKey, pathKey, statusCode)
	}

	response, ok := responseValue.(map[string]any)
	if !ok {
		t.Fatalf("swagger operation %s %s %s response is not an object: %T", methodKey, pathKey, statusCode, responseValue)
	}

	schemaValue, ok := response["schema"]
	if !ok {
		t.Fatalf("swagger operation %s %s %s response missing schema", methodKey, pathKey, statusCode)
	}

	schema, ok := schemaValue.(map[string]any)
	if !ok {
		t.Fatalf("swagger operation %s %s %s schema is not an object: %T", methodKey, pathKey, statusCode, schemaValue)
	}

	refValue, ok := schema["$ref"].(string)
	if !ok {
		t.Fatalf("swagger operation %s %s %s schema missing $ref", methodKey, pathKey, statusCode)
	}
	if refValue != "#/definitions/v1ErrorResponse" {
		t.Fatalf("swagger operation %s %s %s schema ref = %q, want %q", methodKey, pathKey, statusCode, refValue, "#/definitions/v1ErrorResponse")
	}
}
