package cfg

import (
	"fmt"
	"io"
	// "time"

	"github.com/uber/jaeger-client-go"
	jaegerconfig "github.com/uber/jaeger-client-go/config"
)

// InitOpenTracing 初始化全局分布式链路追踪
func (c *LocalConfig) InitOpenTracing() (io.Closer, error) {
	samplerCfg := &jaegerconfig.SamplerConfig{
		Type:  jaeger.SamplerTypeConst,
		Param: 1,
	}

	if c.Opentracing.Host == "" {
		c.Opentracing.Host = "127.0.0.1"
	}
	if c.Opentracing.Port == 0 {
		c.Opentracing.Port = 6831
	}
	tracingHost := fmt.Sprintf("%v:%v", c.Opentracing.Host, c.Opentracing.Port)

	reporterCfg := &jaegerconfig.ReporterConfig{
		// QueueSize: 1,
		// LogSpans:            false,
		// BufferFlushInterval: 3 * time.Second,
		LocalAgentHostPort: tracingHost,
	}

	headerCfg := &jaeger.HeadersConfig{
		TraceContextHeaderName:   TraceContextHeaderName,
		TraceBaggageHeaderPrefix: TraceBaggageHeaderPrefix,
	}

	jaegerCfg := jaegerconfig.Configuration{
		Disabled: !c.Opentracing.Enable,
		Sampler:  samplerCfg,
		Reporter: reporterCfg,
		Headers:  headerCfg}

	closer, err := jaegerCfg.InitGlobalTracer(c.GetServiceName())
	if err != nil {
		return closer, err
	}

	return closer, nil
}
