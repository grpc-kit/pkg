// Package compatibility freezes the public slog API surface introduced in
// v0.5.0. These declarations intentionally mirror CLI-generated code and
// external callers so signature drift fails at compile time.
package compatibility

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"

	"github.com/grpc-kit/pkg/admin"
	"github.com/grpc-kit/pkg/admin/openapiconfig"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/cfg"
	"github.com/grpc-kit/pkg/errs"
	mcptools "github.com/grpc-kit/pkg/mcp/tools"
	"github.com/grpc-kit/pkg/rpc"
	"github.com/grpc-kit/pkg/rpc/interceptors/audit"
	"github.com/grpc-kit/pkg/sd"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/genproto/googleapis/api/serviceconfig"
)

var (
	_ func(*cfg.LocalConfig, context.Context) error                                            = (*cfg.LocalConfig).Init
	_ func(*cfg.LocalConfig, context.Context) error                                            = (*cfg.LocalConfig).Deregister
	_ func(*cfg.LocalConfig, context.Context, *http.ServeMux, fs.FS) error                     = (*cfg.LocalConfig).HTTPHandlerFrontend
	_ func(*cfg.LocalConfig) *slog.Logger                                                      = (*cfg.LocalConfig).GetLogger
	_ func(*cfg.ObjstoreConfig, *slog.Logger) (cfg.ObjstoreBucket, error)                      = (*cfg.ObjstoreConfig).BucketClient
	_ func(*slog.Logger) admin.Options                                                         = admin.WithLogger
	_ func(*slog.Logger) *rpc.Config                                                           = rpc.NewConfig
	_ func(*slog.Logger) audit.Option                                                          = audit.WithLogger
	_ func(*auth.Client, *slog.Logger) *auth.Client                                            = (*auth.Client).WithLoggerOption
	_ func(*slog.Logger, int, string) (*sd.Connector, error)                                   = sd.NewConnector
	_ func(context.Context, *sd.Connector, string, string, string, int64) (sd.Registry, error) = sd.Register
	_ func(sd.Registry, context.Context) error                                                 = sd.Registry.Deregister
	_ func(*errs.Status, context.Context, *slog.Logger, string, error) *errs.Status            = (*errs.Status).WithLogger
	_ func(
		*mcp.Server,
		mcptools.GRPCConnFunc,
		*http.Client,
		string,
		*serviceconfig.Service,
		*openapiconfig.OpenAPIConfig,
		fs.FS,
		string,
		[]string,
		*slog.Logger,
	) error = mcptools.AutoBridge
)

// generatedMicroservice models the logger contract emitted by the v0.5.0
// service template.
type generatedMicroservice struct {
	logger *slog.Logger
}

func newGeneratedMicroservice(localConfig *cfg.LocalConfig) *generatedMicroservice {
	return &generatedMicroservice{logger: localConfig.GetLogger()}
}
