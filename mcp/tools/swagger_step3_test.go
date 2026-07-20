package tools

import (
	"encoding/json"
	"strings"
	"testing"
)

// requireContains 判断 required 列表是否包含 name。
func requireContains(t *testing.T, schema map[string]any, name string, want bool) {
	t.Helper()
	arr, ok := schema["required"].([]string)
	if !ok {
		if want {
			t.Errorf("required not a []string or absent; want %q present", name)
		}
		return
	}
	for _, r := range arr {
		if r == name {
			if !want {
				t.Errorf("required should NOT contain %q, got %v", name, arr)
			}
			return
		}
	}
	if want {
		t.Errorf("required should contain %q, got %v", name, arr)
	}
}

// TestBuildInputSchemaFromSwagger_BodyStar 验证 body="*"：请求消息字段展平到顶层，
// 类型/format 正确，title 提升为 description，自包含无 $ref。
func TestBuildInputSchemaFromSwagger_BodyStar(t *testing.T) {
	doc := loadAdminSwaggerForTest(t)
	idx := buildSwaggerOpIndex(doc)
	op := lookupSwaggerOp(idx, "POST", "/builtin/admin/api/v1/auth/login")

	schema := buildInputSchemaFromSwagger(op, "*", "/builtin/admin/api/v1/auth/login", doc)

	if schema["type"] != "object" {
		t.Fatalf("type = %v", schema["type"])
	}
	props, _ := schema["properties"].(map[string]any)
	for _, f := range []string{"username", "email", "phone_number", "expires_in", "password_hash", "provider_code"} {
		if _, ok := props[f]; !ok {
			t.Errorf("missing flattened body field %q", f)
		}
	}
	ei, _ := props["expires_in"].(map[string]any)
	if ei["type"] != "integer" || ei["format"] != "int32" {
		t.Errorf("expires_in = %v, want integer/int32", ei)
	}
	u, _ := props["username"].(map[string]any)
	if desc, _ := u["description"].(string); !strings.Contains(desc, "系统识别的用户名") {
		t.Errorf("username.description not promoted from title: %q", desc)
	}
	// 无 path/query 参数，故无 required
	if _, has := schema["required"]; has {
		t.Errorf("expected no required for body-only op, got %v", schema["required"])
	}
	// 自包含
	b, _ := json.Marshal(schema)
	if strings.Contains(string(b), "$ref") {
		t.Errorf("schema contains $ref: %s", b)
	}
}

// TestBuildInputSchemaFromSwagger_Query 验证 GET 的 query 参数出现在 schema 且类型正确。
func TestBuildInputSchemaFromSwagger_Query(t *testing.T) {
	doc := loadAdminSwaggerForTest(t)
	idx := buildSwaggerOpIndex(doc)
	op := lookupSwaggerOp(idx, "GET", "/builtin/admin/api/v1/auth/providers")

	schema := buildInputSchemaFromSwagger(op, "", "/builtin/admin/api/v1/auth/providers", doc)
	props, _ := schema["properties"].(map[string]any)

	ps, _ := props["page_size"].(map[string]any)
	if ps == nil || ps["type"] != "integer" {
		t.Errorf("page_size = %v, want integer", ps)
	}
	pt, _ := props["page_token"].(map[string]any)
	if pt == nil || pt["type"] != "string" {
		t.Errorf("page_token = %v, want string", pt)
	}
	// query 参数均非必填
	requireContains(t, schema, "page_size", false)
}

// TestBuildInputSchemaFromSwagger_PathAndQuery 验证 path 参数（必填）与 query 参数（可选）分类正确。
func TestBuildInputSchemaFromSwagger_PathAndQuery(t *testing.T) {
	doc := loadAdminSwaggerForTest(t)
	idx := buildSwaggerOpIndex(doc)
	op := lookupSwaggerOp(idx, "GET", "/builtin/admin/api/v1/auth/callback/{provider_name}")

	schema := buildInputSchemaFromSwagger(op, "", "/builtin/admin/api/v1/auth/callback/{provider_name}", doc)
	props, _ := schema["properties"].(map[string]any)

	pn, _ := props["provider_name"].(map[string]any)
	if pn == nil || pn["type"] != "string" {
		t.Errorf("provider_name = %v, want string", pn)
	}
	requireContains(t, schema, "provider_name", true)  // path 必填
	requireContains(t, schema, "code", false)           // query 可选
	requireContains(t, schema, "state", false)          // query 可选
}

// TestBuildInputSchemaFromSwagger_BodyField 验证 body="fieldname"：字段类型（消息）展平到顶层。
func TestBuildInputSchemaFromSwagger_BodyField(t *testing.T) {
	doc := loadAdminSwaggerForTest(t)
	idx := buildSwaggerOpIndex(doc)
	op := lookupSwaggerOp(idx, "POST", "/builtin/admin/api/v1/auth/providers")

	// gateway body="provider"；swagger body 参数 $ref -> v1AuthProvider（字段类型）
	schema := buildInputSchemaFromSwagger(op, "provider", "/builtin/admin/api/v1/auth/providers", doc)
	props, _ := schema["properties"].(map[string]any)

	// v1AuthProvider 的字段被展平（而非包在 "provider" 下）
	for _, f := range []string{"id", "code", "type", "status", "display_name"} {
		if _, ok := props[f]; !ok {
			t.Errorf("missing flattened v1AuthProvider field %q", f)
		}
	}
	if _, ok := props["provider"]; ok {
		t.Errorf("field type should be flattened, not nested under \"provider\"")
	}
	b, _ := json.Marshal(schema)
	if strings.Contains(string(b), "$ref") {
		t.Errorf("schema contains $ref: %s", b)
	}
}

// TestBuildInputSchemaFromSwagger_NilOp 验证 op=nil 降级为仅 path 参数。
func TestBuildInputSchemaFromSwagger_NilOp(t *testing.T) {
	schema := buildInputSchemaFromSwagger(nil, "", "/v1/items/{id}", nil)
	if schema["type"] != "object" {
		t.Fatalf("type = %v", schema["type"])
	}
	// 降级路径复用 buildInputSchema，其 properties 为 map[string]map[string]string
	// （与 buildInputSchemaFromSwagger 的 map[string]any 在 JSON 上等价）
	props, ok := schema["properties"].(map[string]map[string]string)
	if !ok {
		t.Fatalf("properties type = %T, want map[string]map[string]string", schema["properties"])
	}
	if _, ok := props["id"]; !ok {
		t.Errorf("path param id missing in degraded schema")
	}
	requireContains(t, schema, "id", true)
}

// TestBuildInputSchemaFromSwagger_EmptyBody 验证 body="*" 但请求消息为空对象时不新增字段。
// 构造 fixture：body schema 为 {"type":"object"}（无 properties）。
func TestBuildInputSchemaFromSwagger_EmptyBody(t *testing.T) {
	op := &swaggerOperation{
		Parameters: []swaggerParameter{
			{Name: "body", In: "body", Required: true, Schema: json.RawMessage(`{"type":"object"}`)},
		},
	}
	schema := buildInputSchemaFromSwagger(op, "*", "/v1/empty", nil)
	props, _ := schema["properties"].(map[string]any)
	if len(props) != 0 {
		t.Errorf("empty body should add no fields, got %v", props)
	}
	if _, has := schema["required"]; has {
		t.Errorf("empty body should have no required, got %v", schema["required"])
	}
}

// TestBuildInputSchemaFromSwagger_ScalarBodyField 验证 body="fieldname" 标量字段：
// schema 为基本类型时以 bodyField 为键放入顶层。
func TestBuildInputSchemaFromSwagger_ScalarBodyField(t *testing.T) {
	op := &swaggerOperation{
		Parameters: []swaggerParameter{
			{Name: "body", In: "body", Required: true, Schema: json.RawMessage(`{"type":"string"}`)},
		},
	}
	schema := buildInputSchemaFromSwagger(op, "name", "/v1/scalar", nil)
	props, _ := schema["properties"].(map[string]any)
	sub, ok := props["name"].(map[string]any)
	if !ok {
		t.Fatalf("scalar body field should be keyed by bodyField \"name\", got %v", props)
	}
	if sub["type"] != "string" {
		t.Errorf("name.type = %v, want string", sub["type"])
	}
}
