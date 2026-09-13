package tools

import (
	"io/fs"
	"net/http"

	"github.com/grpc-kit/pkg/admin/openapiconfig"
	"github.com/grpc-kit/pkg/logging/logruscompat"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/api/serviceconfig"
)

// AutoBridge serves legacy callers that supply a logrus entry.
//
// Deprecated: use AutoBridgeWithSlog. This compatibility function will be
// removed when the v0.5.0 slog API cutover restores the AutoBridge name.
func AutoBridge(
	server *mcp.Server,
	connFn GRPCConnFunc,
	httpClient *http.Client,
	httpBaseURL string,
	gatewayCfg *serviceconfig.Service,
	swaggerCfg *openapiconfig.OpenAPIConfig,
	assets fs.FS,
	swaggerAssetName string,
	allowedTags []string,
	logger *logrus.Entry,
) error {
	return AutoBridgeWithSlog(
		server,
		connFn,
		httpClient,
		httpBaseURL,
		gatewayCfg,
		swaggerCfg,
		assets,
		swaggerAssetName,
		allowedTags,
		logruscompat.NewLogger(logger),
	)
}
