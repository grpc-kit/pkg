package cfg

import (
	"context"
	"fmt"

	/*
		"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
		"go.opentelemetry.io/otel/metric"
		sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	*/

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	"google.golang.org/grpc/credentials"
	"os"
	"strings"
)

// InitOpentracing 初始化全局分布式链路追踪
func (c *LocalConfig) InitOpentracing() (interface{}, error) {
	if c.Opentracing == nil {
		c.Opentracing = &OpentracingConfig{
			Enable: false,
		}
	}

	if c.Opentracing.Exporters == nil {
		return nil, nil
	}

	hostName, err := os.Hostname()
	if err != nil || hostName == "" {
		hostName = "unknow"
	}

	ctx := context.Background()
	var bsp sdktrace.SpanProcessor

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

	if c.Opentracing.Exporters.OTLPHTTP != nil {
		tmps := strings.Split(c.Opentracing.Exporters.OTLPHTTP.Endpoint, "//")
		if len(tmps) != 2 {
			return nil, fmt.Errorf("opentracing exporter otlp http endpoint error")
		}

		trurl := c.Opentracing.Exporters.OTLPHTTP.TracesURLPath
		if trurl == "" {
			trurl = "/v1/traces"
		}

		opts := make([]otlptracehttp.Option, 0)
		if strings.HasPrefix(tmps[1], "https") {
			return nil, fmt.Errorf("not support https")
		} else {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		opts = append(opts, otlptracehttp.WithHeaders(c.Opentracing.Exporters.OTLPGRPC.Headers))
		opts = append(opts, otlptracehttp.WithEndpoint(tmps[1]))
		opts = append(opts, otlptracehttp.WithURLPath(trurl))

		traceClientHttp := otlptracehttp.NewClient(opts...)
		otlptracehttp.WithCompression(1)

		traceExp, err := otlptrace.New(ctx, traceClientHttp)
		if err != nil {
			return nil, err
		}

		bsp = sdktrace.NewBatchSpanProcessor(traceExp)
	} else if c.Opentracing.Exporters.OTLPGRPC != nil {
		tmps := strings.Split(c.Opentracing.Exporters.OTLPGRPC.Endpoint, "//")
		if len(tmps) != 2 {
			return nil, fmt.Errorf("opentracing exporter otlp grpc endpoint error")
		}

		opts := make([]otlptracegrpc.Option, 0)
		if strings.HasPrefix(tmps[1], "https") {
			opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")))
		} else {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		opts = append(opts, otlptracegrpc.WithHeaders(c.Opentracing.Exporters.OTLPGRPC.Headers))
		opts = append(opts, otlptracegrpc.WithEndpoint(tmps[1]))

		traceClient := otlptracegrpc.NewClient(opts...)

		traceExp, err := otlptrace.New(ctx, traceClient)
		if err != nil {
			return nil, err
		}

		bsp = sdktrace.NewBatchSpanProcessor(traceExp)

		// TODO; test metrics
		/*
			me, err := otlpmetricgrpc.New(
				context.TODO(),
				otlpmetricgrpc.WithTLSCredentials(creds),
				otlpmetricgrpc.WithEndpoint(tmps[1]),
				otlpmetricgrpc.WithHeaders(c.Opentracing.Exporters.OTLPGRPC.Headers))

			reader := sdkmetric.NewPeriodicReader(
				me,
				sdkmetric.WithInterval(15*time.Second),
			)
			provider := sdkmetric.NewMeterProvider(
				sdkmetric.WithReader(reader),
				sdkmetric.WithResource(res),
			)
			otel.SetMeterProvider(provider)

			meter := provider.Meter("app_or_package_name")
			counter, _ := meter.Int64Counter(
				"grpc_kit.demo.counter_name",
				metric.WithUnit("1"),
				metric.WithDescription("counter description"),
			)

			go func() {
				for {
					counter.Add(ctx, 1)
					time.Sleep(10 * time.Second)
					c.logger.Infof("add metrics")
				}
			}()
		*/

	} else if c.Opentracing.Exporters.Logging != nil {
		opts := make([]stdouttrace.Option, 0)
		if c.Opentracing.Exporters.Logging.PrettyPrint {
			opts = append(opts, stdouttrace.WithPrettyPrint())
		}
		if c.Opentracing.Exporters.Logging.FilePath != "" && c.Opentracing.Exporters.Logging.FilePath != "stdout" {
			f, err := os.OpenFile(c.Opentracing.Exporters.Logging.FilePath, os.O_RDWR|os.O_CREATE, 0755)
			if err != nil {
				return nil, err
			}
			opts = append(opts, stdouttrace.WithWriter(f))
		}

		traceExp, err := stdouttrace.New(opts...)
		if err != nil {
			return nil, err
		}
		bsp = sdktrace.NewBatchSpanProcessor(traceExp)
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
	)

	otel.SetTextMapPropagator(propagation.TraceContext{})
	otel.SetTracerProvider(tracerProvider)

	return nil, err
}
