package rpc

import (
	"github.com/grpc-kit/pkg/logging/logruscompat"
	"github.com/sirupsen/logrus"
)

// NewConfig returns a Config backed by a legacy logrus entry.
//
// Deprecated: use NewConfigWithSlog.
func NewConfig(logger *logrus.Entry) *Config {
	return NewConfigWithSlog(logruscompat.NewLogger(logger))
}
