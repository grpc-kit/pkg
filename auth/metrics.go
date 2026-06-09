package auth

import "github.com/prometheus/client_golang/prometheus"

// Phase 1 P9：策略加载/刷新可观测指标。
//
// 仅 3 个指标（与 roadmap §6.2 P9 行一一对应）：
//   - auth_policy_reload_total{result="ok"|"fail"} —— 启动初始化与每次 Reload 触发计数
//   - auth_policy_loader_duration_seconds         —— initOPARego（含 DataProvider.Load）总耗时
//   - auth_action_lookup_miss_total               —— mergeGrpcKitInput 反查 action_id 为空次数
//
// 注册策略：包级单例 + init() 注册到 prometheus.DefaultRegisterer，
// 与 pkg/cfg/prometheus.go::InitPrometheus 通过 prometheus.MustRegister(reg)
// 把子 Registry 链上 DefaultRegisterer 的方式兼容；NewClient 多次调用不会
// 触发重复注册 panic（指标是包级变量，注册一次）。
//
// 失败模式：注册若 panic（极少数情况，例如下游业务在 DefaultRegisterer 上注册过
// 同名 collector），init() 会让 import "github.com/grpc-kit/pkg/auth" 直接失败，
// 这是合理的 fail-fast —— 同名冲突必须在编译/启动阶段暴露。
var (
	metricReloadTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "auth_policy_reload_total",
			Help: "Total number of OPA Rego policy reloads, partitioned by result.",
		},
		[]string{"result"},
	)

	metricLoaderDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "auth_policy_loader_duration_seconds",
			Help: "Wall-clock duration of OPA Rego policy load (including DataProvider invocation).",
			// 覆盖 1ms ~ 32s；DB 全量加载典型为几十~几百 ms，超过 1s 则需告警。
			Buckets: prometheus.ExponentialBuckets(0.001, 2, 16),
		},
	)

	metricActionLookupMiss = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "auth_action_lookup_miss_total",
			Help: "Number of requests whose action_id could not be resolved from StaticDict (RPCRoutes/GatewayRoutes).",
		},
	)
)

func init() {
	// 直接注册到 DefaultRegisterer；通过 promauto 也可，但显式 MustRegister
	// 与 pkg/cfg/prometheus.go::InitPrometheus 一致更易审计。
	prometheus.MustRegister(
		metricReloadTotal,
		metricLoaderDuration,
		metricActionLookupMiss,
	)
}
