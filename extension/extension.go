package extension

import "github.com/grpc-kit/pkg/cfg"

// Extension 扩展接口
type Extension interface {
	Name() string
	Init(config *cfg.LocalConfig) error
}
