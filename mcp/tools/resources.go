package tools

import (
	"context"
	"fmt"
	"io"
	"io/fs"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// BuiltinResourcesConfig 汇总内置 Resources 注册所需的输入。
//
// 各字段由 pkg/cfg 调用方注入，避免 pkg/mcp/tools 反向依赖 pkg/vars / pkg/admin。
type BuiltinResourcesConfig struct {
	// VersionText 是 /version 端点返回的版本 JSON（vars.GetVersion().String()）。
	VersionText string

	// MicroserviceSwaggerFS / MicroserviceSwaggerName：微服务 swagger 资产。
	// 来自 adminServer.GetMicroserviceGatewaySwaggerJSON()；资产位于 openapi/<name>.swagger.json。
	// 二者为空时跳过 grpc-kit://openapi-spec/microservice 注册。
	MicroserviceSwaggerFS   fs.FS
	MicroserviceSwaggerName string

	// AdminEnabled 控制是否注册 grpc-kit://openapi-spec/admin。
	// 对应 c.Services.hasEnableIntegrationAdminServer()。
	AdminEnabled bool

	// AdminSwaggerFS 是框架内置 admin 服务的 swagger 资产（adminv1.Assets）。
	// 仅当 AdminEnabled=true 时使用；资产位于 openapi/admin.swagger.json。
	AdminSwaggerFS fs.FS
}

// 内置 resource 的 URI、Name 与常量。
//
// scheme 采用 grpc-kit:// 命名空间，与业务自定义资源（走扩展点、用各自 domain scheme）隔离；
// swagger 路径用 openapi-spec，对齐已有 HTTP 端点 /openapi-spec。
const (
	builtinVersionURI             = "grpc-kit://version"
	builtinOpenAPIMicroserviceURI = "grpc-kit://openapi-spec/microservice"
	builtinOpenAPIAdminURI        = "grpc-kit://openapi-spec/admin"

	builtinVersionName             = "version"
	builtinOpenAPIMicroserviceName = "openapi-microservice"
	builtinOpenAPIAdminName        = "openapi-admin"

	mimeJSON            = "application/json"
	adminSwaggerAssetPath = "openapi/admin.swagger.json"
)

// 资源描述：落实 swagger 是「面向业务开发者的 REST 接口文档、AI 经 tools 调用而非直接打 REST」的定位。
const (
	descVersion = "服务版本与构建信息（appname/releaseVersion/gitCommit/buildDate/goVersion 等）"

	descOpenAPIMicroservice = "微服务的 RESTful API 文档（OpenAPI 2.0），面向业务开发者。" +
		"描述方法、参数与响应 schema，可据此理解 API 结构与数据形态。" +
		"注意：这些是 REST 接口，AI 应通过 MCP tools 调用对应能力，不要直接调用 REST 端点。"

	descOpenAPIAdmin = "框架内置 admin 服务的 RESTful API 文档，面向业务开发者。" +
		"其方法默认不作为 MCP tool 暴露，AI 仅供参考、不可经 MCP 调用。"
)

// RegisterBuiltinResources 注册框架内置 Resources：version + openapi-spec(microservice[/admin])。
//
// 这些 resource 镜像已公开的 HTTP 端点（/version、/openapi-spec），不引入新安全面
//（与被移除的 get_config 内部运行配置暴露本质不同，见 ADR-009）。
//
// nil/缺失保护：
//   - server == nil：直接返回。
//   - VersionText 为空仍注册 version resource（返回空文本），保持资源可发现。
//   - 微服务 swagger 资产缺失：跳过 microservice resource。
//   - AdminEnabled=false 或 admin 资产缺失：跳过 admin resource。
//
// 幂等：AddResource 对同 URI 为覆盖语义，可安全重复调用。
func RegisterBuiltinResources(server *mcp.Server, cfg BuiltinResourcesConfig) {
	if server == nil {
		return
	}

	// grpc-kit://version
	server.AddResource(&mcp.Resource{
		URI:         builtinVersionURI,
		Name:        builtinVersionName,
		Description: descVersion,
		MIMEType:    mimeJSON,
	}, func(ctx context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{URI: builtinVersionURI, MIMEType: mimeJSON, Text: cfg.VersionText},
			},
		}, nil
	})

	// grpc-kit://openapi-spec/microservice
	if cfg.MicroserviceSwaggerFS != nil && cfg.MicroserviceSwaggerName != "" {
		path := "openapi/" + cfg.MicroserviceSwaggerName + ".swagger.json"
		server.AddResource(&mcp.Resource{
			URI:         builtinOpenAPIMicroserviceURI,
			Name:        builtinOpenAPIMicroserviceName,
			Description: descOpenAPIMicroservice,
			MIMEType:    mimeJSON,
		}, func(ctx context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			text, err := readAsset(cfg.MicroserviceSwaggerFS, path)
			if err != nil {
				return nil, fmt.Errorf("read microservice swagger: %w", err)
			}
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{
					{URI: builtinOpenAPIMicroserviceURI, MIMEType: mimeJSON, Text: text},
				},
			}, nil
		})
	}

	// grpc-kit://openapi-spec/admin（条件注册）
	if cfg.AdminEnabled && cfg.AdminSwaggerFS != nil {
		server.AddResource(&mcp.Resource{
			URI:         builtinOpenAPIAdminURI,
			Name:        builtinOpenAPIAdminName,
			Description: descOpenAPIAdmin,
			MIMEType:    mimeJSON,
		}, func(ctx context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			text, err := readAsset(cfg.AdminSwaggerFS, adminSwaggerAssetPath)
			if err != nil {
				return nil, fmt.Errorf("read admin swagger: %w", err)
			}
			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{
					{URI: builtinOpenAPIAdminURI, MIMEType: mimeJSON, Text: text},
				},
			}, nil
		})
	}
}

// readAsset 从 FS 读取文件全文为字符串。
func readAsset(fsys fs.FS, path string) (string, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
