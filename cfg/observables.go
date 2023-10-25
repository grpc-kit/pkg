package cfg

import (
	"context"
	"fmt"
	"os"
	"strings"

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
)

// ObservablesConfig 用于客观性配置
type ObservablesConfig struct {
	tracer *sdktrace.TracerProvider

	Enable bool `mapstructure:"enable"`

	Telemetry *struct {
		Traces *struct {
			// 给定一个 0 至 1 之间的分数决定采样频率
			SampleRatio float64 `mapstructure:"sample_ratio"`

			// 记录特殊字段，默认不开启
			LogFields struct {
				HTTPBody     bool `mapstructure:"http_body"`
				HTTPResponse bool `mapstructure:"http_response"`
			} `mapstructure:"log_fields"`

			// 过滤器，用于过滤不需要追踪的请求
			Filters []struct {
				Method  string `mapstructure:"method"`
				URLPath string `mapstructure:"url_path"`
			} `mapstructure:"filters"`
		}
	} `mapstructure:"telemetry"`

	Exporters *struct {
		OTLPGRPC *OTLPGRPCConfig `mapstructure:"otlp"`
		OTLPHTTP *OTLPHTTPConfig `mapstructure:"otlphttp"`
		Logging  *struct {
			FilePath    string `mapstructure:"file_path"`
			PrettyPrint bool   `mapstructure:"pretty_print"`
		} `mapstructure:"logging"`
	} `mapstructure:"exporters"`
}

// InitObservables 初始化可观测性配置
func (c *LocalConfig) InitObservables() (interface{}, error) {
	if c.Observables == nil {
		c.Observables = &ObservablesConfig{
			Enable: false,
		}
	}

	if !c.Observables.Enable {
		return nil, nil
	}

	if c.Observables.Exporters == nil {
		return nil, fmt.Errorf("at least one exporter")
	}

	hostName, err := os.Hostname()
	if err != nil || hostName == "" {
		hostName = "unknow"
	}

	ctx := context.Background()
	// var bsp sdktrace.SpanProcessor

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

	// 控制采样频率
	sampleRatio := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.2))
	if c.Observables.Telemetry != nil {
		if c.Observables.Telemetry.Traces != nil {
			ratio := c.Observables.Telemetry.Traces.SampleRatio
			if ratio >= 1 {
				sampleRatio = sdktrace.AlwaysSample()
			} else if ratio > 0 {
				sampleRatio = sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
			} else {
				sampleRatio = sdktrace.NeverSample()
			}
		}
	}

	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sampleRatio),
		sdktrace.WithResource(res),
	)
	c.Observables.tracer = tracerProvider

	if err = c.initExportOTLPGRPC(ctx); err != nil {
		return nil, err
	}
	if err = c.initExportOTLPHTTP(ctx); err != nil {
		return nil, err
	}
	if err = c.initExportLogging(ctx); err != nil {
		return nil, err
	}

	otel.SetTextMapPropagator(propagation.TraceContext{})
	otel.SetTracerProvider(tracerProvider)

	return nil, nil
}

func (c *LocalConfig) initExportOTLPGRPC(ctx context.Context) error {
	if !c.Observables.Enable {
		return nil
	}
	if c.Observables.Exporters == nil || c.Observables.Exporters.OTLPGRPC == nil {
		return nil
	}

	tmps := strings.Split(c.Observables.Exporters.OTLPGRPC.Endpoint, "//")
	if len(tmps) != 2 {
		return fmt.Errorf("opentracing exporter otlp grpc endpoint error")
	}

	opts := make([]otlptracegrpc.Option, 0)
	if strings.HasPrefix(tmps[0], "https") {
		opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")))
	} else {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	opts = append(opts, otlptracegrpc.WithHeaders(c.Observables.Exporters.OTLPGRPC.Headers))
	opts = append(opts, otlptracegrpc.WithEndpoint(tmps[1]))

	client := otlptracegrpc.NewClient(opts...)
	exp, err := otlptrace.New(ctx, client)
	if err != nil {
		return err
	}

	bsp := sdktrace.NewBatchSpanProcessor(exp)
	c.Observables.tracer.RegisterSpanProcessor(bsp)

	return nil
}

func (c *LocalConfig) initExportOTLPHTTP(ctx context.Context) error {
	if !c.Observables.Enable {
		return nil
	}
	if c.Observables.Exporters == nil || c.Observables.Exporters.OTLPHTTP == nil {
		return nil
	}

	tmps := strings.Split(c.Observables.Exporters.OTLPHTTP.Endpoint, "//")
	if len(tmps) != 2 {
		return fmt.Errorf("opentracing exporter otlp http endpoint error")
	}

	trurl := c.Observables.Exporters.OTLPHTTP.TracesURLPath
	if trurl == "" {
		trurl = "/v1/traces"
	}

	opts := make([]otlptracehttp.Option, 0)
	if strings.HasPrefix(tmps[0], "https") {
	} else {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	opts = append(opts, otlptracehttp.WithHeaders(c.Observables.Exporters.OTLPHTTP.Headers))
	opts = append(opts, otlptracehttp.WithEndpoint(tmps[1]))
	opts = append(opts, otlptracehttp.WithURLPath(trurl))

	client := otlptracehttp.NewClient(opts...)
	otlptracehttp.WithCompression(1)

	exp, err := otlptrace.New(ctx, client)
	if err != nil {
		return err
	}

	bsp := sdktrace.NewBatchSpanProcessor(exp)
	c.Observables.tracer.RegisterSpanProcessor(bsp)

	return nil
}

func (c *LocalConfig) initExportLogging(ctx context.Context) error {
	if !c.Observables.Enable {
		return nil
	}
	if c.Observables.Exporters == nil || c.Observables.Exporters.Logging == nil {
		return nil
	}

	opts := make([]stdouttrace.Option, 0)
	if c.Observables.Exporters.Logging.PrettyPrint {
		opts = append(opts, stdouttrace.WithPrettyPrint())
	}
	if c.Observables.Exporters.Logging.FilePath != "" && c.Observables.Exporters.Logging.FilePath != "stdout" {
		f, err := os.OpenFile(c.Observables.Exporters.Logging.FilePath, os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			return err
		}
		opts = append(opts, stdouttrace.WithWriter(f))
	}

	exp, err := stdouttrace.New(opts...)
	if err != nil {
		return err
	}
	bsp := sdktrace.NewBatchSpanProcessor(exp)
	c.Observables.tracer.RegisterSpanProcessor(bsp)

	return nil
}
