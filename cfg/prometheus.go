package cfg

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// InitPrometheus 用于初始化可观测性
func (c *LocalConfig) InitPrometheus() error {
	reg := prometheus.NewRegistry()
	prometheus.MustRegister(reg)

	// Add Go module build info.
	reg.MustRegister(collectors.NewBuildInfoCollector())

	// Add go runtime metrics and process collectors.
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	c.promRegistry = reg

	return nil
}
