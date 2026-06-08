package auth

import "context"

// Config xx
type Config struct {
	PackageName string
	Partition   string // GRN partition 段，默认 "grpc-kit"（详见 docs/spec/grn.md）
	OPASDK      *OPASDKConfig
	OPARego     *OPARegoConfig
	OPAEnvoy    *OPAEnvoyPluginConfig

	// StaticDict 由 *.gateway.yaml + *.openapiv2.yaml 派生的服务/路由字典。
	// 若非 nil，initOPARego 会把 BuildOPAData() 的内容合并到 OPA inmem store
	// 的 data.<PackageName> 命名空间下（与既有 RBAC keys 平级）。
	//
	// 设计约束：
	//   - 仅注入，本期（Phase 1 P3）Rego 不消费这些 key；
	//   - 与既有 RBAC keys 冲突时静态字典优先（services/rpc_routes/gateway_routes 为保留键）；
	//   - 详见 adm/docs/roadmap/permission-opa-policy-loader.md §6.2 P3。
	StaticDict *StaticDict
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
