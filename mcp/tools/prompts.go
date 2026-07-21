package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const gettingStartedPromptName = "getting_started"

// RegisterGettingStartedPrompt 注册框架唯一内置 Prompt：getting_started。
//
// 设计要点（见 Phase 9 / ADR-010）：
//   - 服务名取自 microservice swagger 的 info.title（如 oneops-netdev-v1），不使用 "grpc-kit" 字样作服务标识。
//   - prompt 文本不含 "grpc-kit"：不硬编码 grpc-kit:// URI，改让 LLM 用 resources/list / tools/list 协议发现、按 resource Name 取用。
//   - 明确 openapi-* 是 REST 开发者文档，AI 经 tools 调用、勿直接打 REST 端点。
//
// swaggerFS/swaggerName 用于读取 info.title；读取失败时开头文案退化为「你已连接到本服务的 MCP 端点」。
// server 为 nil 时直接返回。幂等：AddPrompt 对同名 prompt 为覆盖语义。
func RegisterGettingStartedPrompt(server *mcp.Server, swaggerFS fs.FS, swaggerName string) {
	if server == nil {
		return
	}
	title := readSwaggerTitle(swaggerFS, swaggerName)

	server.AddPrompt(&mcp.Prompt{
		Name:        gettingStartedPromptName,
		Title:       "首次使用指引",
		Description: "首次连接或不确定如何提问时调用：建立对服务能力的认知，并给出高效提问与安全调用原则。可选传入 task 获取针对性建议。",
		Arguments: []*mcp.PromptArgument{
			{Name: "task", Description: "你打算完成的任务，用于给出针对性的工具选择与调用建议"},
		},
	}, func(ctx context.Context, req *mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		task := ""
		if req != nil && req.Params != nil && req.Params.Arguments != nil {
			task = strings.TrimSpace(req.Params.Arguments["task"])
		}
		return &mcp.GetPromptResult{
			Messages: []*mcp.PromptMessage{
				{Role: mcp.Role("user"), Content: &mcp.TextContent{Text: buildGettingStartedText(title, task)}},
			},
		}, nil
	})
}

// readSwaggerTitle 从 microservice swagger 资产读取 info.title。
// 资产缺失/解析失败时返回空串（调用方据此退化文案）。
func readSwaggerTitle(swaggerFS fs.FS, swaggerName string) string {
	if swaggerFS == nil || swaggerName == "" {
		return ""
	}
	text, err := readAsset(swaggerFS, "openapi/"+swaggerName+".swagger.json")
	if err != nil {
		return ""
	}
	var info struct {
		Info struct {
			Title string `json:"title"`
		} `json:"info"`
	}
	if err := json.Unmarshal([]byte(text), &info); err != nil {
		return ""
	}
	return strings.TrimSpace(info.Info.Title)
}

// buildGettingStartedText 拼装 getting_started prompt 的消息文本。
//
// title 注入开头作服务名；task 非空时末尾追加针对性建议段。
// 全文不含 "grpc-kit"，资源引用改为按 Name（version / openapi-microservice / openapi-admin），
// 由 LLM 经 resources/list 发现。
func buildGettingStartedText(title, task string) string {
	header := "你已连接到本服务的 MCP 端点。这是首次使用指引，回答用户前请先建立对服务能力的认知。"
	if title != "" {
		header = fmt.Sprintf("你已连接到 %s 的 MCP 端点。这是首次使用指引，回答用户前请先建立对服务能力的认知。", title)
	}
	body := `

【1. 建立认知】
- 调用 tools/list 查看可执行工具（对应微服务的 gRPC 方法，已按 mcp tag 过滤）。AI 通过这些工具调用服务能力。
- 调用 resources/list 查看可用资源：读取名为 version 的资源确认服务版本与构建信息；读取 openapi-microservice 资源了解 RESTful API 的方法分组、参数字段与响应 schema（admin 管理面见 openapi-admin）。
- 注意：openapi-* 资源是面向业务开发者的 REST 接口文档，供你理解 API 结构与数据形态；请勿直接调用这些 REST 端点，一切操作通过 tools 完成。

【2. 提问与调用原则】
1) 具体化目标：明确实体（名称/ID/命名空间），避免"某个"、"所有"等模糊指代；信息不足先向用户澄清。
2) 先读后写：对破坏性操作（工具注解 DestructiveHint=true，如删除/修改类）先调用对应查询工具核对目标，确认后再执行，必要时向用户二次确认。
3) 对齐数据结构：调用前可查阅 openapi-microservice 资源确认参数字段名与类型，勿凭猜测构造请求。
4) 分页与规模：列表类工具结果不完整时按分页参数继续拉取，勿假设一次取全；大批量操作分步进行。
5) 错误处理：调用失败时按返回的 status/错误码向用户解释并给出下一步。

【3. 建议首轮动作】
先用查询类（GET）工具探查用户关心对象的现状，再决定是否需要变更。`
	out := header + body
	if task != "" {
		out += fmt.Sprintf("\n\n（若提供 task）\n用户任务：%s\n请据此：在 openapi-microservice 资源中按 tags/summary 定位相关方法 -> 优先用查询工具摸清现状 -> 再判断是否执行变更并按上述原则操作。", task)
	}
	return out
}
