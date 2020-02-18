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

	return c
}
