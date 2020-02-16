package rpc

import (
	"time"
)

type Config struct {
	GRPCAddress      string
	HTTPAddress      string
	KeepaliveTimeout time.Duration
}
