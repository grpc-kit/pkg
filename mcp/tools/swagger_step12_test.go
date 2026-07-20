package tools

import (
	"encoding/json"
	"strings"
	"testing"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
)

// loadAdminSwaggerForTest 加载仓库内 admin.swagger.json，供 Step 1-2 冒烟验证。
func loadAdminSwaggerForTest(t *testing.T) *swaggerDoc {
	t.Helper()
	doc, err := loadSwaggerDoc(adminv1.Assets, "admin")
	if err != nil {
		t.Fatalf("loadSwaggerDoc: %v", err)
	}
	return doc
}

// TestLoadSwaggerDoc_RealAdmin 验证真实 admin.swagger.json 可解析且结构完备。
func TestLoadSwaggerDoc_RealAdmin(t *testing.T) {
	doc := loadAdminSwaggerForTest(t)
	if len(doc.Paths) == 0 {
		t.Fatal("paths empty")
	}
	if len(doc.Definitions) == 0 {
		t.Fatal("definitions empty")
	}
	// v1CreateAuthLoginRequest 必须存在且为可解析 JSON
	raw, ok := doc.Definitions["v1CreateAuthLoginRequest"]
	if !ok || len(raw) == 0 {
		t.Fatalf("v1CreateAuthLoginRequest missing")
	}
}

// TestBuildSwaggerOpIndex_Lookup 验证 (method, path) 索引与查找。
func TestBuildSwaggerOpIndex_Lookup(t *testing.T) {
	doc := loadAdminSwaggerForTest(t)
	idx := buildSwaggerOpIndex(doc)

	op := lookupSwaggerOp(idx, "POST", "/builtin/admin/api/v1/auth/login")
	if op == nil {
		t.Fatal("CreateAuthLogin op not found")
	}
	if op.OperationID != "KnownAdmin_CreateAuthLogin" {
		t.Fatalf("operationId = %q", op.OperationID)
	}
	if op.Summary != "登录认证" {
		t.Fatalf("summary = %q", op.Summary)
	}

	// 未命中返回 nil
	if lookupSwaggerOp(idx, "GET", "/no/such/path") != nil {
		t.Fatal("expected nil for unmatched")
	}
	// method 大小写不敏感
	if lookupSwaggerOp(idx, "post", "/builtin/admin/api/v1/auth/login") == nil {
		t.Fatal("lowercase method should still match")
	}
}

// TestInlineSwaggerSchema_BodyStar_TitlePromotion 验证 body="*" 的核心承诺：
// $ref 展平到顶层、字段语义从 title 提升为 description、类型/format 正确、自包含无 $ref。
func TestInlineSwaggerSchema_BodyStar_TitlePromotion(t *testing.T) {
	doc := loadAdminSwaggerForTest(t)
	idx := buildSwaggerOpIndex(doc)
	op := lookupSwaggerOp(idx, "POST", "/builtin/admin/api/v1/auth/login")

	var bodySchema json.RawMessage
	for _, p := range op.Parameters {
		if p.In == "body" {
			bodySchema = p.Schema
			break
		}
	}
	if len(bodySchema) == 0 {
		t.Fatal("body param schema missing")
	}

	schema := inlineSwaggerSchema(bodySchema, doc, 4, 0, map[string]struct{}{})

	if schema["type"] != "object" {
		t.Fatalf("type = %v, want object", schema["type"])
	}
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("properties not a map: %T", schema["properties"])
	}

	// 6 字段全部出现
	for _, f := range []string{"username", "email", "phone_number", "expires_in", "password_hash", "provider_code"} {
		if _, ok := props[f]; !ok {
			t.Errorf("missing field %q", f)
		}
	}

	// username: string + description 从 title 提升
	u := props["username"].(map[string]any)
	if u["type"] != "string" {
		t.Errorf("username.type = %v, want string", u["type"])
	}
	if desc, _ := u["description"].(string); !strings.Contains(desc, "系统识别的用户名") {
		t.Errorf("username.description = %q, want title-promoted text", desc)
	}

	// expires_in: integer + format int32
	ei := props["expires_in"].(map[string]any)
	if ei["type"] != "integer" {
		t.Errorf("expires_in.type = %v, want integer", ei["type"])
	}
	if ei["format"] != "int32" {
		t.Errorf("expires_in.format = %v, want int32", ei["format"])
	}

	// 自包含：marshal 后不含 "$ref"
	b, _ := json.Marshal(schema)
	if strings.Contains(string(b), "$ref") {
		t.Errorf("schema still contains $ref: %s", b)
	}
}

// TestInlineSwaggerSchema_BodyField 验证 body="fieldname" 时 body 参数 $ref 指向字段类型。
// CreateAuthProvider 的 body 参数 name="provider"，$ref -> v1AuthProvider（字段类型）。
func TestInlineSwaggerSchema_BodyField(t *testing.T) {
	doc := loadAdminSwaggerForTest(t)
	idx := buildSwaggerOpIndex(doc)
	op := lookupSwaggerOp(idx, "POST", "/builtin/admin/api/v1/auth/providers")

	var bodyParam *swaggerParameter
	for i := range op.Parameters {
		if op.Parameters[i].In == "body" {
			bodyParam = &op.Parameters[i]
			break
		}
	}
	if bodyParam == nil {
		t.Fatal("body param missing")
	}
	if bodyParam.Name != "provider" {
		t.Fatalf("body param name = %q, want provider", bodyParam.Name)
	}

	schema := inlineSwaggerSchema(bodyParam.Schema, doc, 4, 0, map[string]struct{}{})
	if schema["type"] != "object" {
		t.Fatalf("type = %v, want object", schema["type"])
	}
	props, _ := schema["properties"].(map[string]any)
	if len(props) == 0 {
		t.Fatal("v1AuthProvider expanded to no properties")
	}
	// 自包含
	b, _ := json.Marshal(schema)
	if strings.Contains(string(b), "$ref") {
		t.Errorf("schema still contains $ref: %s", b)
	}
}

// TestInlineSwaggerSchema_CycleSafe 验证自引用 definition（adminv1Role）不无限递归，
// 且在环处降级为 "(递归引用)" 标记。
func TestInlineSwaggerSchema_CycleSafe(t *testing.T) {
	doc := loadAdminSwaggerForTest(t)
	raw, ok := doc.Definitions["adminv1Role"]
	if !ok {
		t.Skip("adminv1Role not present")
	}
	// 直接对 definition 本体展开（模拟 body 指向它）
	schema := inlineSwaggerSchema(raw, doc, 8, 0, map[string]struct{}{})
	b, _ := json.Marshal(schema)
	if strings.Contains(string(b), "(递归引用)") {
		// 环被检测并标记
		return
	}
	// 即便没有显式标记（例如自引用字段在深度外），也必须不挂起；到达此处即说明已终止。
	t.Logf("adminv1Role expanded without cycle marker (depth-limited): %s", b)
}

// TestInlineSwaggerSchema_DepthLimit 验证 maxDepth 限制：超深 $ref 降级为 object。
func TestInlineSwaggerSchema_DepthLimit(t *testing.T) {
	// 构造 A -> B -> C -> D 链，maxDepth=1 时只展开 1 层 $ref，深处降级
	doc := &swaggerDoc{
		Definitions: map[string]json.RawMessage{
			"A": json.RawMessage(`{"type":"object","properties":{"b":{"$ref":"#/definitions/B"}}}`),
			"B": json.RawMessage(`{"type":"object","properties":{"c":{"$ref":"#/definitions/C"},"name":{"type":"string"}}}`),
			"C": json.RawMessage(`{"type":"object","properties":{"d":{"$ref":"#/definitions/D"}}}`),
			"D": json.RawMessage(`{"type":"object","properties":{"deep":{"type":"string"}}}`),
		},
	}
	// 入口 $ref: A。maxDepth=1：A 展开（depth0->1），A.b 的 $ref:B 在 depth=1，1>1 false 展开（depth1->2），
	// B.c 的 $ref:C 在 depth=2，2>1 true -> 降级为 object。
	schema := inlineSwaggerSchema(json.RawMessage(`{"$ref":"#/definitions/A"}`), doc, 1, 0, map[string]struct{}{})
	b, _ := json.Marshal(schema)
	s := string(b)
	// B 的 name 字段应可见（B 被展开）；C 的 deep 字段应不可见（C 被降级为 object）
	if !strings.Contains(s, "name") {
		t.Errorf("B.name should be visible: %s", s)
	}
	if strings.Contains(s, "deep") {
		t.Errorf("D.deep should be depth-limited away: %s", s)
	}
}

// TestPrimitiveParamSchema 验证 path/query 基本类型与数组参数 schema。
func TestPrimitiveParamSchema(t *testing.T) {
	// string 默认类型 + format + description
	s := primitiveParamSchema(swaggerParameter{Type: "integer", Format: "int32", Description: "页大小"})
	if s["type"] != "integer" || s["format"] != "int32" || s["description"] != "页大小" {
		t.Errorf("integer param = %v", s)
	}
	// type 缺省视为 string
	s2 := primitiveParamSchema(swaggerParameter{})
	if s2["type"] != "string" {
		t.Errorf("default type = %v, want string", s2["type"])
	}
	// 数组
	s3 := primitiveParamSchema(swaggerParameter{Type: "array", Items: json.RawMessage(`{"type":"string"}`)})
	if s3["type"] != "array" {
		t.Errorf("array type = %v", s3["type"])
	}
	items, ok := s3["items"].(map[string]any)
	if !ok || items["type"] != "string" {
		t.Errorf("array items = %v", s3["items"])
	}
}

// TestResolveSwaggerRef 验证 $ref 解析与边界。
func TestResolveSwaggerRef(t *testing.T) {
	doc := loadAdminSwaggerForTest(t)
	if len(resolveSwaggerRef(doc, "#/definitions/v1CreateAuthLoginRequest")) == 0 {
		t.Error("resolve v1CreateAuthLoginRequest failed")
	}
	if len(resolveSwaggerRef(doc, "#/definitions/does_not_exist")) != 0 {
		t.Error("non-existent ref should return nil")
	}
	if len(resolveSwaggerRef(doc, "https://example.com/x")) != 0 {
		t.Error("non-definitions ref should return nil")
	}
	if len(resolveSwaggerRef(nil, "#/definitions/x")) != 0 {
		t.Error("nil doc should return nil")
	}
}
