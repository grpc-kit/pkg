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
	TLS *TLSConfig
}

// TLSConfig
type TLSConfig struct {
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
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
