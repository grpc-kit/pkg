package rpc

import (
	"time"
)

// Config server config
type Config struct {
	GRPCAddress      string
	HTTPAddress      string
	KeepaliveTimeout time.Duration
}
