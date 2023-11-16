package rpc

import (
	"time"

	"github.com/sirupsen/logrus"
)

// Config server config
type Config struct {
	logger *logrus.Entry

	GRPCAddress string
	HTTPAddress string

	KeepaliveTimeout time.Duration

	// client
	Scheme      string
	Authority   string
	APIEndpoint string

	// tls
	TLS TLSConfig
}

// TLSConfig xx
type TLSConfig struct {
	// HTTPCertFile 用于 HTTP 网关证书
	HTTPCertFile string
	HTTPKeyFile  string

	// 用于基于 acme 协议的自动化证书申请
	ACMEServer   string
	ACMEEmail    string
	ACMEDomains  []string
	ACMECacheDir string
}

// NewConfig xx
func NewConfig(l *logrus.Entry) *Config {
	c := &Config{
		logger: l,
	}

	if c.logger == nil {
		c.logger = logrus.NewEntry(logrus.New())
	}

	// default values
	c.KeepaliveTimeout = 20 * time.Second
	c.Scheme = "grpc-kit"

	return c
}
