package tools

import (
	"encoding/json"
	"strings"
	"testing"
)

// rawArgs 是构造 args map 的便捷函数。
func rawArgs(kv ...string) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = json.RawMessage(kv[i+1])
	}
	return out
}

// parseBody 将 body RawMessage 解析为 map，便于断言。
func parseBody(t *testing.T, b json.RawMessage) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("parse body %q: %v", string(b), err)
	}
	return m
}

// TestBuildRequestBody_BodyStar 验证 body="*"：非 path/query 参数作为 flat JSON body。
func TestBuildRequestBody_BodyStar(t *testing.T) {
	doc := loadAdminSwaggerForTest(t)
	idx := buildSwaggerOpIndex(doc)
	op := lookupSwaggerOp(idx, "POST", "/builtin/admin/api/v1/auth/login")

	body, ok := buildRequestBody(rawArgs("username", `"alice"`, "password_hash", `"x"`), op, "/builtin/admin/api/v1/auth/login", "*")
	if !ok {
		t.Fatal("expected ok")
	}
	m := parseBody(t, body)
	if m["username"] != "alice" || m["password_hash"] != "x" {
		t.Errorf("body = %v, want flat {username,password_hash}", m)
	}
}

// TestBuildRequestBody_BodyField_NoWrap 验证 body="fieldname"（消息字段）：flat 不包装。
// 实证（admin.pb.gw.go: Decode(&protoReq.Provider)）：body 应为字段值本身，
// 即 {"code":...,"display_name":...}，而非 {"provider":{...}}。
func TestBuildRequestBody_BodyField_NoWrap(t *testing.T) {
	doc := loadAdminSwaggerForTest(t)
	idx := buildSwaggerOpIndex(doc)
	op := lookupSwaggerOp(idx, "POST", "/builtin/admin/api/v1/auth/providers")

	body, ok := buildRequestBody(rawArgs("code", `"local"`, "display_name", `"Local"`), op, "/builtin/admin/api/v1/auth/providers", "provider")
	if !ok {
		t.Fatal("expected ok")
	}
	m := parseBody(t, body)
	if m["code"] != "local" || m["display_name"] != "Local" {
		t.Errorf("body = %v, want flat {code,display_name}", m)
	}
	if _, wrapped := m["provider"]; wrapped {
		t.Errorf("body must NOT wrap under \"provider\": %v", m)
	}
}

// TestBuildRequestBody_Empty 验证无 body 参数时返回 "{}"。
func TestBuildRequestBody_Empty(t *testing.T) {
	doc := loadAdminSwaggerForTest(t)
	idx := buildSwaggerOpIndex(doc)
	op := lookupSwaggerOp(idx, "POST", "/builtin/admin/api/v1/auth/login")

	body, ok := buildRequestBody(rawArgs(), op, "/builtin/admin/api/v1/auth/login", "*")
	if !ok {
		t.Fatal("expected ok for empty body args")
	}
	if string(body) != "{}" {
		t.Errorf("empty body = %q, want {}", string(body))
	}
}

// TestBuildRequestBody_BodyFieldEmpty 验证 bodyField="" 返回 (nil, false)。
func TestBuildRequestBody_BodyFieldEmpty(t *testing.T) {
	body, ok := buildRequestBody(rawArgs("a", `"b"`), &swaggerOperation{}, "/v1/x", "")
	if ok || body != nil {
		t.Errorf("bodyField=\"\" should return (nil,false), got (%q,%v)", string(body), ok)
	}
}

// TestBuildRequestBody_Scalar 验证 body="fieldname"（标量字段）：发送字段原始 JSON 值。
func TestBuildRequestBody_Scalar(t *testing.T) {
	op := &swaggerOperation{
		Parameters: []swaggerParameter{
			{Name: "body", In: "body", Required: true, Schema: json.RawMessage(`{"type":"string"}`)},
		},
	}
	body, ok := buildRequestBody(rawArgs("name", `"hello"`), op, "/v1/scalar", "name")
	if !ok {
		t.Fatal("expected ok")
	}
	if string(body) != `"hello"` {
		t.Errorf("scalar body = %q, want \"hello\"", string(body))
	}
}

// TestBuildRequestBody_QueryExcluded 验证 query 参数被排除出 body。
func TestBuildRequestBody_QueryExcluded(t *testing.T) {
	op := &swaggerOperation{
		Parameters: []swaggerParameter{
			{Name: "q", In: "query", Type: "string"},
			{Name: "body", In: "body", Required: true, Schema: json.RawMessage(`{"$ref":"#/definitions/X"}`)},
		},
	}
	body, ok := buildRequestBody(rawArgs("q", `"x"`, "name", `"alice"`), op, "/v1/x", "*")
	if !ok {
		t.Fatal("expected ok")
	}
	m := parseBody(t, body)
	if _, leaked := m["q"]; leaked {
		t.Errorf("query param q must not appear in body: %v", m)
	}
	if m["name"] != "alice" {
		t.Errorf("body = %v, want {name}", m)
	}
}

// TestBuildRequestBody_NilOp 验证 op=nil 退化为「非 path 即 body」。
func TestBuildRequestBody_NilOp(t *testing.T) {
	body, ok := buildRequestBody(rawArgs("foo", `"bar"`), nil, "/v1/x", "*")
	if !ok {
		t.Fatal("expected ok")
	}
	m := parseBody(t, body)
	if m["foo"] != "bar" {
		t.Errorf("body = %v, want {foo:bar}", m)
	}
}

// TestBuildRequestBody_PathExcluded 验证 path 参数被排除出 body。
func TestBuildRequestBody_PathExcluded(t *testing.T) {
	op := &swaggerOperation{
		Parameters: []swaggerParameter{
			{Name: "id", In: "path", Type: "string"},
			{Name: "body", In: "body", Required: true, Schema: json.RawMessage(`{"$ref":"#/definitions/X"}`)},
		},
	}
	body, ok := buildRequestBody(rawArgs("id", `"1"`, "name", `"alice"`), op, "/v1/x/{id}", "*")
	if !ok {
		t.Fatal("expected ok")
	}
	m := parseBody(t, body)
	if _, leaked := m["id"]; leaked {
		t.Errorf("path param id must not appear in body: %v", m)
	}
	if m["name"] != "alice" {
		t.Errorf("body = %v, want {name}", m)
	}
}

// TestAppendQueryParams_Basic 验证 query 参数构建（命名、值编码）。
func TestAppendQueryParams_Basic(t *testing.T) {
	op := &swaggerOperation{
		Parameters: []swaggerParameter{
			{Name: "page_size", In: "query", Type: "integer"},
			{Name: "filter", In: "query", Type: "string"},
		},
	}
	out := appendQueryParams("http://x/api", "/api", op, rawArgs("page_size", "10", "filter", `"active"`))
	// url.Values.Encode 按键排序：filter,page_size
	if out != "http://x/api?filter=active&page_size=10" {
		t.Errorf("query = %q", out)
	}
}

// TestAppendQueryParams_Array 验证数组参数重复参数名。
func TestAppendQueryParams_Array(t *testing.T) {
	op := &swaggerOperation{
		Parameters: []swaggerParameter{{Name: "tag", In: "query", Type: "array"}},
	}
	out := appendQueryParams("http://x/api", "/api", op, rawArgs("tag", `["a","b"]`))
	if !strings.Contains(out, "tag=a") || !strings.Contains(out, "tag=b") {
		t.Errorf("array query = %q, want tag=a&tag=b", out)
	}
}

// TestAppendQueryParams_EmptySkipped 验证空字符串与 null 被跳过。
func TestAppendQueryParams_EmptySkipped(t *testing.T) {
	op := &swaggerOperation{
		Parameters: []swaggerParameter{
			{Name: "filter", In: "query", Type: "string"},
			{Name: "page_size", In: "query", Type: "integer"},
		},
	}
	out := appendQueryParams("http://x/api", "/api", op, rawArgs("filter", `""`, "page_size", "10"))
	if strings.Contains(out, "filter") {
		t.Errorf("empty filter should be skipped: %q", out)
	}
	if !strings.Contains(out, "page_size=10") {
		t.Errorf("page_size should remain: %q", out)
	}
	out2 := appendQueryParams("http://x/api", "/api", op, rawArgs("filter", "null", "page_size", "10"))
	if strings.Contains(out2, "filter") {
		t.Errorf("null filter should be skipped: %q", out2)
	}
}

// TestAppendQueryParams_NilOp 验证 op=nil 时所有非 path 参数走 query。
func TestAppendQueryParams_NilOp(t *testing.T) {
	out := appendQueryParams("http://x/api/{id}", "/api/{id}", nil, rawArgs("id", `"1"`, "a", "1", "b", `"x"`))
	if strings.Contains(out, "id=") {
		t.Errorf("path param id should be excluded: %q", out)
	}
	if !strings.Contains(out, "a=1") || !strings.Contains(out, "b=x") {
		t.Errorf("non-path args should be query: %q", out)
	}
}

// TestAppendQueryParams_None 验证无 query 参数时 URL 原样返回。
func TestAppendQueryParams_None(t *testing.T) {
	op := &swaggerOperation{
		Parameters: []swaggerParameter{{Name: "q", In: "query", Type: "string"}},
	}
	out := appendQueryParams("http://x/api", "/api", op, rawArgs())
	if out != "http://x/api" {
		t.Errorf("no query -> url unchanged, got %q", out)
	}
}

// TestLookupOpDocs_SwaggerPriority 验证 swagger 优先于 docMap。
func TestLookupOpDocs_SwaggerPriority(t *testing.T) {
	op := &swaggerOperation{Summary: "sw-sum", Description: "sw-desc", Tags: []string{"sw-tag"}}
	docMap := map[string]swaggerMethod{"svc/Method": {summary: "dm-sum", description: "dm-desc", tags: []string{"dm-tag"}}}
	sum, desc, tags := lookupOpDocs(op, docMap, "svc/Method")
	if sum != "sw-sum" || desc != "sw-desc" || len(tags) != 1 || tags[0] != "sw-tag" {
		t.Errorf("swagger should win: sum=%q desc=%q tags=%v", sum, desc, tags)
	}
}

// TestLookupOpDocs_DocMapFallback 验证 op=nil 时 docMap 兜底。
func TestLookupOpDocs_DocMapFallback(t *testing.T) {
	docMap := map[string]swaggerMethod{"svc/Method": {summary: "dm-sum", description: "dm-desc", tags: []string{"dm-tag"}}}
	sum, desc, tags := lookupOpDocs(nil, docMap, "svc/Method")
	if sum != "dm-sum" || desc != "dm-desc" || len(tags) != 1 || tags[0] != "dm-tag" {
		t.Errorf("docMap fallback: sum=%q desc=%q tags=%v", sum, desc, tags)
	}
}

// TestLookupOpDocs_PartialFallback 验证 swagger 缺失字段由 docMap 补齐。
func TestLookupOpDocs_PartialFallback(t *testing.T) {
	op := &swaggerOperation{Summary: "sw-sum"} // 无 description/tags
	docMap := map[string]swaggerMethod{"svc/Method": {description: "dm-desc", tags: []string{"dm-tag"}}}
	sum, desc, tags := lookupOpDocs(op, docMap, "svc/Method")
	if sum != "sw-sum" {
		t.Errorf("summary = %q, want sw-sum", sum)
	}
	if desc != "dm-desc" {
		t.Errorf("description = %q, want dm-desc (fallback)", desc)
	}
	if len(tags) != 1 || tags[0] != "dm-tag" {
		t.Errorf("tags = %v, want [dm-tag] (fallback)", tags)
	}
}
