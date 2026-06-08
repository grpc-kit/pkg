package auth

import "context"

// Config xx
type Config struct {
	PackageName string
	Partition   string // GRN partition 段，默认 "grpc-kit"（详见 docs/spec/grn.md）
	OPASDK      *OPASDKConfig
	OPARego     *OPARegoConfig
	OPAEnvoy    *OPAEnvoyPluginConfig
}

type OPASDKConfig struct {
	Config string
}

type OPARegoConfig struct {
	// Rego 静态 Rego 策略源码（旧字段名：RegoBody）。
	Rego []byte
	// Data 静态 OPA data JSON（旧字段名：DataBody）。
	Data []byte
	// DataProvider 动态数据提供函数，优先级高于 Data（旧字段名：DataProviderFunc）。
	// 若函数返回空或错误，则降级到 Data；Data 也为空时使用框架内置默认规则。
	DataProvider func(ctx context.Context) ([]byte, error)
}

type OPAEnvoyPluginConfig struct {
	GRPCAddress string
}
