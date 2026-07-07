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
	RegoBody []byte
	DataBody []byte
	// DataProviderFunc 动态数据提供函数，优先级高于 DataBody。
	// 若函数返回空或错误，则降级到 DataBody；DataBody 也为空时使用框架内置默认规则。
	DataProviderFunc func(ctx context.Context) ([]byte, error)
}

type OPAEnvoyPluginConfig struct {
	GRPCAddress string
}
