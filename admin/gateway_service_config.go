package admin

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"

	"github.com/grpc-kit/pkg/admin/openapiconfig"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"google.golang.org/genproto/googleapis/api/serviceconfig"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"
)

func parseMicroserviceGatewayYAML(data []byte) (*serviceconfig.Service, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}

	jsonBody, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("convert microservice gateway yaml to json: %w", err)
	}

	out := &serviceconfig.Service{}
	unmarshalOptions := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := unmarshalOptions.Unmarshal(jsonBody, out); err != nil {
		return nil, fmt.Errorf("unmarshal microservice gateway yaml to service config: %w", err)
	}

	return out, nil
}

func parseMicroserviceSwaggerYAML(data []byte) (*openapiconfig.OpenAPIConfig, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("microservice gateway yaml is empty")
	}

	jsonBody, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("convert microservice gateway yaml to json: %w", err)
	}

	out := &openapiconfig.OpenAPIConfig{}
	unmarshalOptions := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := unmarshalOptions.Unmarshal(jsonBody, out); err != nil {
		return nil, fmt.Errorf("unmarshal microservice gateway yaml to service config: %w", err)
	}

	return out, nil
}

func (c *config) setMicroserviceGatewayYAML(assets fs.FS) error {
	if c == nil {
		return fmt.Errorf("admin config is nil")
	}

	// 保留 assets FS 供 AutoBridge 加载 openapi/microservice.swagger.json（Phase 6）。
	c.microserviceGatewayAssets = assets

	// 解析 gateway.yaml
	gatewayFile, err := assets.Open("openapi/microservice.gateway.yaml")
	if err != nil {
		return fmt.Errorf("open microservice gateway yaml: %w", err)
	}

	gatewayYAML, err := io.ReadAll(gatewayFile)
	if err != nil {
		return fmt.Errorf("read microservice gateway yaml: %w", err)
	}
	_ = gatewayFile.Close()

	gatewayParsed, err := parseMicroserviceGatewayYAML(gatewayYAML)
	if err != nil {
		return fmt.Errorf("parse microservice gateway yaml: %w", err)
	}
	c.microserviceGatewayServiceConfig = gatewayParsed

	adminFile, err := adminv1.Assets.ReadFile("openapi/admin.gateway.yaml")
	if err != nil {
		return fmt.Errorf("read known admin gateway yaml: %w", err)
	}

	adminParsed, err := parseMicroserviceGatewayYAML(adminFile)
	if err != nil {
		return fmt.Errorf("parse known admin gateway yaml: %w", err)
	}
	c.knownAdminGatewayServiceConfig = adminParsed

	// 解析 swagger.yaml
	swaggerFile, err := assets.Open("openapi/microservice.openapiv2.yaml")
	if err != nil {
		return fmt.Errorf("open microservice gateway yaml: %w", err)
	}

	swaggerYAML, err := io.ReadAll(swaggerFile)
	if err != nil {
		return fmt.Errorf("read microservice gateway yaml: %w", err)
	}
	_ = swaggerFile.Close()

	swaggerParsed, err := parseMicroserviceSwaggerYAML(swaggerYAML)
	if err != nil {
		return fmt.Errorf("open microservice gateway yaml: %w", err)
	}
	c.microserviceGatewaySwagger = swaggerParsed

	adminSwaggerFile, err := adminv1.Assets.ReadFile("openapi/admin.openapiv2.yaml")
	if err != nil {
		return fmt.Errorf("read known admin gateway yaml: %w", err)
	}

	adminSwaggerParsed, err := parseMicroserviceSwaggerYAML(adminSwaggerFile)
	if err != nil {
		return fmt.Errorf("unmarshal microservice gateway yaml to service config: %w", err)
	}
	c.knownAdminGatewaySwagger = adminSwaggerParsed

	return err
}

func (a *KnownAdminAPI) getMicroserviceGatewayServiceConfig() (*serviceconfig.Service, error) {
	if a == nil || a.config == nil || a.config.microserviceGatewayServiceConfig == nil {
		return nil, fmt.Errorf("microservice gateway config is nil")
	}

	return a.config.microserviceGatewayServiceConfig, nil
}

// GetMicroserviceGatewayServiceConfig 公开的 gateway 配置访问器，委托给私有方法。
// 该方法在内部错误（如配置未加载）时返回 (nil, error)，由调用方按需处理。
func (a *KnownAdminAPI) GetMicroserviceGatewayServiceConfig() (*serviceconfig.Service, error) {
	return a.getMicroserviceGatewayServiceConfig()
}

func (a *KnownAdminAPI) getMicroserviceGatewaySwagger() (*openapiconfig.OpenAPIConfig, error) {
	if a == nil || a.config == nil || a.config.microserviceGatewaySwagger == nil {
		return nil, fmt.Errorf("microservice gateway openapiv2 is nil")
	}

	return a.config.microserviceGatewaySwagger, nil
}

// GetMicroserviceGatewaySwagger 公开的 swagger 配置访问器，委托给私有方法。
// 该方法在内部错误（如配置未加载）时返回 (nil, error)，由调用方按需处理。
func (a *KnownAdminAPI) GetMicroserviceGatewaySwagger() (*openapiconfig.OpenAPIConfig, error) {
	return a.getMicroserviceGatewaySwagger()
}

// microserviceSwaggerAssetName 是微服务 swagger 资产基名（与 microservice.gateway.yaml 同源）。
const microserviceSwaggerAssetName = "microservice"

// GetMicroserviceGatewaySwaggerJSON 返回微服务网关资产 FS 与 swagger 资产基名，
// 供 AutoBridge 侧 loadSwaggerDoc 加载 openapi/<name>.swagger.json（Phase 6）。
// 未调用 SetMicroserviceGatewayYAML 时 assets 为 nil，调用方应降级为仅 path 参数。
func (a *KnownAdminAPI) GetMicroserviceGatewaySwaggerJSON() (fs.FS, string) {
	if a == nil || a.config == nil {
		return nil, microserviceSwaggerAssetName
	}
	return a.config.microserviceGatewayAssets, microserviceSwaggerAssetName
}

func (a *KnownAdminAPI) getKnownAdminGatewayServiceConfig() (*serviceconfig.Service, error) {
	if a == nil || a.config == nil || a.config.knownAdminGatewayServiceConfig == nil {
		return nil, fmt.Errorf("known admin gateway config is nil")
	}

	return a.config.knownAdminGatewayServiceConfig, nil
}

func (a *KnownAdminAPI) getKnownAdminGatewaySwagger() (*openapiconfig.OpenAPIConfig, error) {
	if a == nil || a.config == nil || a.config.knownAdminGatewaySwagger == nil {
		return nil, fmt.Errorf("known admin gateway openapiv2 is nil")
	}

	return a.config.knownAdminGatewaySwagger, nil
}
