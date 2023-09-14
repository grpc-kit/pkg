package cfg

import (
	"context"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
)

// InitOpentracing 初始化全局分布式链路追踪
func (c *LocalConfig) InitOpentracing() (interface{}, error) {
	if c.Opentracing == nil {
		c.Opentracing = &OpentracingConfig{
			Enable: false,
		}
	}

	ctx := context.Background()

	traceClientHttp := otlptracehttp.NewClient(
		otlptracehttp.WithEndpoint(c.Opentracing.Host),
		otlptracehttp.WithURLPath(c.Opentracing.URLPath),
		otlptracehttp.WithInsecure())
	otlptracehttp.WithCompression(1)

	hostName, err := os.Hostname()
	if err != nil || hostName == "" {
		hostName = "unknow"
	}

	traceExp, err := otlptrace.New(ctx, traceClientHttp)
	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithAttributes(
			// 在可观测链路 OpenTelemetry 版后端显示的服务名称。
			semconv.ServiceNameKey.String(c.GetServiceName()),
			// 在可观测链路 OpenTelemetry 版后端显示的主机名称。
			semconv.HostNameKey.String(hostName),
		),
	)

	bsp := sdktrace.NewBatchSpanProcessor(traceExp)
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
	)

	otel.SetTextMapPropagator(propagation.TraceContext{})
	otel.SetTracerProvider(tracerProvider)

	return nil, err
}
