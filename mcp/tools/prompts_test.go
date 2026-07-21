package tools

import (
	"context"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// microserviceSwaggerFS 构造一个含给定 info.title 的 microservice swagger 资产 FS。
func microserviceSwaggerFS(title string) fstest.MapFS {
	body := `{"swagger":"2.0","info":{"title":"` + title + `"},"paths":{}}`
	return fstest.MapFS{
		"openapi/microservice.swagger.json": &fstest.MapFile{Data: []byte(body)},
	}
}

func TestGettingStartedPrompt_NoTask(t *testing.T) {
	hs := newBuiltinTestServer(t, func(s *mcp.Server) {
		RegisterGettingStartedPrompt(s, microserviceSwaggerFS("oneops-netdev-v1"), "microservice")
	})
	session := connectTestClient(t, hs.URL)

	// prompts/list 含 getting_started
	lr, err := session.ListPrompts(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}
	found := false
	for _, p := range lr.Prompts {
		if p.Name == "getting_started" {
			found = true
		}
	}
	if !found {
		t.Fatal("getting_started prompt not listed")
	}

	// prompts/get 无 task：含服务 title、不含 grpc-kit、不含 task 段
	res, err := session.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: "getting_started"})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(res.Messages) == 0 {
		t.Fatal("empty messages")
	}
	tc, ok := res.Messages[0].Content.(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected *TextContent, got %T", res.Messages[0].Content)
	}
	if !strings.Contains(tc.Text, "oneops-netdev-v1") {
		t.Errorf("expected text to contain service title, got: %s", tc.Text)
	}
	if strings.Contains(tc.Text, "grpc-kit") {
		t.Errorf("prompt text must not contain 'grpc-kit': %s", tc.Text)
	}
	if strings.Contains(tc.Text, "用户任务") {
		t.Errorf("did not expect task segment when no task provided: %s", tc.Text)
	}
}

func TestGettingStartedPrompt_WithTask(t *testing.T) {
	hs := newBuiltinTestServer(t, func(s *mcp.Server) {
		RegisterGettingStartedPrompt(s, microserviceSwaggerFS("oneops-netdev-v1"), "microservice")
	})
	session := connectTestClient(t, hs.URL)

	res, err := session.GetPrompt(context.Background(), &mcp.GetPromptParams{
		Name:      "getting_started",
		Arguments: map[string]string{"task": "查询所有交换机的 VLAN"},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	tc, ok := res.Messages[0].Content.(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected *TextContent, got %T", res.Messages[0].Content)
	}
	if !strings.Contains(tc.Text, "查询所有交换机的 VLAN") {
		t.Errorf("expected text to contain task, got: %s", tc.Text)
	}
	if !strings.Contains(tc.Text, "用户任务") {
		t.Errorf("expected task segment when task provided, got: %s", tc.Text)
	}
}

func TestGettingStartedPrompt_TitleFallback(t *testing.T) {
	// 无 swagger 资产 -> title 退化为「本服务」
	hs := newBuiltinTestServer(t, func(s *mcp.Server) {
		RegisterGettingStartedPrompt(s, nil, "")
	})
	session := connectTestClient(t, hs.URL)

	res, err := session.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: "getting_started"})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	tc, ok := res.Messages[0].Content.(*mcp.TextContent)
	if !ok {
		t.Fatalf("expected *TextContent, got %T", res.Messages[0].Content)
	}
	if !strings.Contains(tc.Text, "你已连接到本服务的 MCP 端点") {
		t.Errorf("expected fallback header when title absent, got: %s", tc.Text)
	}
	if strings.Contains(tc.Text, "grpc-kit") {
		t.Errorf("prompt text must not contain 'grpc-kit': %s", tc.Text)
	}
}

func TestGettingStartedPrompt_NilServer(t *testing.T) {
	// 不应 panic
	RegisterGettingStartedPrompt(nil, nil, "")
}

func TestBuildGettingStartedText_NoGrpcKit(t *testing.T) {
	// 直接校验文本拼装：无论是否含 title/task，都不应出现 "grpc-kit"
	for _, tc := range []struct {
		title string
		task  string
	}{
		{"oneops-netdev-v1", ""},
		{"", "做某事"},
		{"svc", "做某事"},
	} {
		got := buildGettingStartedText(tc.title, tc.task)
		if strings.Contains(got, "grpc-kit") {
			t.Errorf("title=%q task=%q: text contains 'grpc-kit': %s", tc.title, tc.task, got)
		}
	}
}
