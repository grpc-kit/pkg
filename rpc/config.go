package rpc

import (
	"log/slog"
	"time"

	"github.com/grpc-kit/pkg/logging"
	"google.golang.org/grpc"
)

// Config server config
type Config struct {
	logger *slog.Logger

	GRPCAddress string
	HTTPAddress string

	KeepaliveTimeout time.Duration

	// client
	Scheme      string
	Authority   string
	APIEndpoint string

	// tls
	TLS TLSConfig

	// 默认开启 http 与 grpc 服务
	DisableGRPCServer bool
	DisableHTTPServer bool

	opts []grpc.ServerOption
}

// TLSConfig xx
type TLSConfig struct {
	// HTTPCertFile 用于 HTTP 网关证书
	HTTPCertFile string
	HTTPKeyFile  string

	// GRPCCertFile 用于 GRPC 网关证书
	GRPCCertFile string
	GRPCKeyFile  string
	// 用于验证客户端证书有效性，既：http_service.tls_client.cert_file 所签发的 ca 证书
	GRPCCAFile string

	// 用于基于 acme 协议的自动化证书申请
	ACMEServer   string
	ACMEEmail    string
	ACMEDomains  []string
	ACMECacheDir string
}

// NewConfigWithSlog returns a Config backed by logger.
func NewConfigWithSlog(logger *slog.Logger) *Config {
	c := &Config{
		logger: logging.OrFallback(logger),
		opts:   []grpc.ServerOption{},
	}

	// default values
	c.KeepaliveTimeout = 20 * time.Second
	c.Scheme = "grpc-kit"

	return c
}

func (c *Config) WithServerOption(opt ...grpc.ServerOption) {
	c.opts = append(c.opts, opt...)
}
