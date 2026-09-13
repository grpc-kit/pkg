// Package compatibility freezes the public logrus API surface during the
// staged slog migration. These declarations intentionally mirror legacy CLI
// generated code and external callers rather than production implementation.
package compatibility

import (
	"io/fs"
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
	"github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/api/serviceconfig"
)

var (
	_ func(*cfg.LocalConfig) *logrus.Entry                                 = (*cfg.LocalConfig).GetLogger
	_ func(*cfg.ObjstoreConfig, *logrus.Entry) (cfg.ObjstoreBucket, error) = (*cfg.ObjstoreConfig).BucketClient
	_ func(*logrus.Entry) admin.Options                                    = admin.WithLogger
	_ func(*logrus.Entry) *rpc.Config                                      = rpc.NewConfig
	_ func(*logrus.Entry) audit.Option                                     = audit.WithLogger
	_ func(*auth.Client, *logrus.Entry) *auth.Client                       = (*auth.Client).WithLoggerOption
	_ func(*logrus.Entry, int, string) (*sd.Connector, error)              = sd.NewConnector
	_ func(*errs.Status, *logrus.Entry, string, error) *errs.Status        = (*errs.Status).WithLogger
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
		*logrus.Entry,
	) error = mcptools.AutoBridge
)

// legacyGeneratedMicroservice models the logger contract emitted by the
// pre-slog service template. It must keep compiling throughout the announced
// CLI compatibility window.
type legacyGeneratedMicroservice struct {
	logger *logrus.Entry
}

func newLegacyGeneratedMicroservice(localConfig *cfg.LocalConfig) *legacyGeneratedMicroservice {
	return &legacyGeneratedMicroservice{logger: localConfig.GetLogger()}
}
