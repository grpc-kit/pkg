package admin

import (
	"bytes"
	"fmt"

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

func (c *config) setMicroserviceGatewayYAML(data []byte) error {
	if c == nil {
		return fmt.Errorf("admin config is nil")
	}

	parsed, err := parseMicroserviceGatewayYAML(data)
	c.microserviceGatewayServiceConfig = parsed

	rawBody, err := adminv1.Assets.ReadFile("admin.gateway.yaml")
	if err != nil {
		return fmt.Errorf("read known admin gateway yaml: %w", err)
	}

	parsedKnownAdmin, err := parseMicroserviceGatewayYAML(rawBody)
	c.knownAdminGatewayServiceConfig = parsedKnownAdmin

	return err
}

func (a *KnownAdminAPI) getMicroserviceGatewayServiceConfig() (*serviceconfig.Service, error) {
	if a == nil || a.config == nil {
		return nil, fmt.Errorf("admin config is nil")
	}

	return a.config.microserviceGatewayServiceConfig, nil
}

func (a *KnownAdminAPI) getKnownAdminGatewayServiceConfig() (*serviceconfig.Service, error) {
	if a == nil || a.config == nil {
		return nil, fmt.Errorf("admin config is nil")
	}

	return a.config.knownAdminGatewayServiceConfig, nil
}