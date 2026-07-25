package tools

import (
	"context"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	mcpserver "github.com/grpc-kit/pkg/mcp"
)

// newBuiltinTestServer 创建一个 MCP Server，调用 register 注册资源/prompt，挂到 httptest.Server。
// 供 resources_test.go 与 prompts_test.go 共用。
func newBuiltinTestServer(t *testing.T, register func(*mcp.Server)) *httptest.Server {
	t.Helper()
	srv, err := mcpserver.NewServer(true, "streamable_http")
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if srv == nil {
		t.Fatalf("expected non-nil server")
	}
	register(srv.MCPServer())
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

// connectTestClient 连接 MCP Client，返回 session（自动 Close）。
func connectTestClient(t *testing.T, url string) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	transport := &mcp.StreamableClientTransport{Endpoint: url}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "0.0.1"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	return session
}

// listResourceNames 返回 server 上 resources/list 中的 resource Name 集合。
func listResourceNames(t *testing.T, session *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := session.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	out := make(map[string]bool, len(res.Resources))
	for _, r := range res.Resources {
		out[r.Name] = true
	}
	return out
}

func TestRegisterBuiltinResources_NilServer(t *testing.T) {
	// 不应 panic
	RegisterBuiltinResources(nil, BuiltinResourcesConfig{})
}

func TestRegisterBuiltinResources_Version(t *testing.T) {
	want := `{"appname":"test-svc","releaseVersion":"1.0.0"}`
	hs := newBuiltinTestServer(t, func(s *mcp.Server) {
		RegisterBuiltinResources(s, BuiltinResourcesConfig{VersionText: want})
	})
	session := connectTestClient(t, hs.URL)

	res, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "grpc-kit://version"})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(res.Contents) == 0 {
		t.Fatal("empty contents")
	}
	if res.Contents[0].Text != want {
		t.Errorf("version text = %q, want %q", res.Contents[0].Text, want)
	}
	if res.Contents[0].MIMEType != "application/json" {
		t.Errorf("mimeType = %q, want application/json", res.Contents[0].MIMEType)
	}
}

func TestRegisterBuiltinResources_OpenAPIMicroservice(t *testing.T) {
	swaggerBody := `{"swagger":"2.0","info":{"title":"demo-svc"},"paths":{}}`
	swaggerFS := fstest.MapFS{
		"openapi/microservice.swagger.json": &fstest.MapFile{Data: []byte(swaggerBody)},
	}
	hs := newBuiltinTestServer(t, func(s *mcp.Server) {
		RegisterBuiltinResources(s, BuiltinResourcesConfig{
			MicroserviceSwaggerFS:   swaggerFS,
			MicroserviceSwaggerName: "microservice",
		})
	})
	session := connectTestClient(t, hs.URL)

	// resources/list 含 version + openapi-microservice，不含 admin
	names := listResourceNames(t, session)
	if !names["version"] {
		t.Error("expected version resource")
	}
	if !names["openapi-microservice"] {
		t.Error("expected openapi-microservice resource")
	}
	if names["openapi-admin"] {
		t.Error("did not expect openapi-admin (AdminEnabled=false)")
	}

	res, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "grpc-kit://openapi-spec/microservice"})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(res.Contents) == 0 || res.Contents[0].Text != swaggerBody {
		got := ""
		if len(res.Contents) > 0 {
			got = res.Contents[0].Text
		}
		t.Errorf("microservice swagger = %q, want %q", got, swaggerBody)
	}
}

func TestRegisterBuiltinResources_OpenAPIAdmin(t *testing.T) {
	adminBody := `{"swagger":"2.0","info":{"title":"known-admin-v1"},"paths":{}}`
	adminFS := fstest.MapFS{
		"openapi/admin.swagger.json": &fstest.MapFile{Data: []byte(adminBody)},
	}
	hs := newBuiltinTestServer(t, func(s *mcp.Server) {
		RegisterBuiltinResources(s, BuiltinResourcesConfig{
			AdminEnabled:   true,
			AdminSwaggerFS: adminFS,
		})
	})
	session := connectTestClient(t, hs.URL)

	names := listResourceNames(t, session)
	if !names["openapi-admin"] {
		t.Fatal("expected openapi-admin resource when AdminEnabled=true")
	}

	res, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "grpc-kit://openapi-spec/admin"})
	if err != nil {
		t.Fatalf("ReadResource: %v", err)
	}
	if len(res.Contents) == 0 || res.Contents[0].Text != adminBody {
		got := ""
		if len(res.Contents) > 0 {
			got = res.Contents[0].Text
		}
		t.Errorf("admin swagger = %q, want %q", got, adminBody)
	}
}

func TestRegisterBuiltinResources_AdminDisabled(t *testing.T) {
	hs := newBuiltinTestServer(t, func(s *mcp.Server) {
		RegisterBuiltinResources(s, BuiltinResourcesConfig{AdminEnabled: false})
	})
	session := connectTestClient(t, hs.URL)
	if names := listResourceNames(t, session); names["openapi-admin"] {
		t.Error("did not expect openapi-admin when AdminEnabled=false")
	}
}
