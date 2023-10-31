package cfg

import (
	"context"
	"fmt"
	"github.com/prometheus/common/version"
	"net/http"
	"os"
	"path"
	"runtime/debug"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	apimetric "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// ObservablesConfig 用于客观性配置
type ObservablesConfig struct {
	tracer       *sdktrace.TracerProvider
	promRegistry *prometheus.Registry

	Enable bool `mapstructure:"enable"`

	Telemetry *struct {
		Traces *struct {
			// 给定一个 0 至 1 之间的分数决定采样频率
			SampleRatio float64 `mapstructure:"sample_ratio"`

			// 记录特殊字段，默认不开启
			LogFields struct {
				HTTPRequest  bool `mapstructure:"http_request"`
				HTTPResponse bool `mapstructure:"http_response"`
			} `mapstructure:"log_fields"`

			// 过滤器，用于过滤不需要追踪的请求
			Filters []struct {
				Method  string `mapstructure:"method"`
				URLPath string `mapstructure:"url_path"`
			} `mapstructure:"filters"`
		} `mapstructure:"traces"`
	} `mapstructure:"telemetry"`

	Exporters *struct {
		OTLPGRPC *OTLPGRPCConfig `mapstructure:"otlp"`
		OTLPHTTP *OTLPHTTPConfig `mapstructure:"otlphttp"`
		Logging  *struct {
			FilePath       string `mapstructure:"file_path"`
			MetricFilePath string `mapstructure:"metric_file_path"`
			PrettyPrint    bool   `mapstructure:"pretty_print"`
		} `mapstructure:"logging"`
	} `mapstructure:"exporters"`
}

// OTLPHTTPConfig xx
type OTLPHTTPConfig struct {
	// The target URL to send data to (e.g.: http://some.url:9411).
	Endpoint      string            `mapstructure:"endpoint"`
	TracesURLPath string            `mapstructure:"traces_url_path"`
	Headers       map[string]string `mapstructure:"headers"`
}

// OTLPGRPCConfig xx
type OTLPGRPCConfig struct {
	// The target URL to send data to (e.g.: http://some.url:9411).
	Endpoint string            `mapstructure:"endpoint"`
	Headers  map[string]string `mapstructure:"headers"`
}

// LogFields 开启请求追踪属性
/*
type LogFields struct {
	HTTPRequest  bool `mapstructure:"http_request"`
	HTTPResponse bool `mapstructure:"http_response"`
}
*/

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

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithProcessOwner(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithOSType(),
		resource.WithProcessExecutablePath(),
		resource.WithAttributes(
			// 在可观测链路 OpenTelemetry 版后端显示的服务名称。
			semconv.ServiceName(c.GetServiceName()),
			// 在可观测链路 OpenTelemetry 版后端显示的主机名称。
			semconv.HostName(hostName),
			semconv.ServiceVersion(version.Revision),
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

	if err = c.Observables.initExportOTLPGRPC(ctx); err != nil {
		return nil, err
	}
	if err = c.Observables.initExportOTLPHTTP(ctx); err != nil {
		return nil, err
	}
	if err = c.Observables.initExportLogging(ctx); err != nil {
		return nil, err
	}

	otel.SetTextMapPropagator(propagation.TraceContext{})
	otel.SetTracerProvider(tracerProvider)

	// TODO, metrics test
	/*
		if err = c.Observables.initExporterPrometheus(ctx, c.GetServiceName()); err != nil {
			return nil, err
		}
	*/
	c.Observables.initPrometheusRegistry()

	c.Observables.initExporterPrometheus(ctx, c.GetServiceName())
	// c.Observables.initExportLoggingMetric(ctx)
	// TODO, metrics test

	return nil, nil
}

func (c *ObservablesConfig) initPrometheusRegistry() {
	// 初始化 prometheus registery 实例
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
}

func (c *ObservablesConfig) initExporterPrometheus(ctx context.Context, serviceName string) error {
	if c.promRegistry == nil {
		return nil
	}

	exp1, err := otelprometheus.New(
		// 使用自定义的 prometheus registery 实例
		otelprometheus.WithRegisterer(c.promRegistry),
		// 避免对每个指标添加额外的 otel_scope_info 标签
		otelprometheus.WithoutScopeInfo(),
	)
	if err != nil {
		return err
	}

	// 避免使用 WithFromEnv 以防止不必要的信息泄漏，如 token 等
	res, err := resource.New(ctx,
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithProcessOwner(),
		resource.WithOSType(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version.Revision),
		),
	)
	if err != nil {
		return err
	}

	// test logging
	if c.Exporters == nil || c.Exporters.Logging == nil || c.Exporters.Logging.MetricFilePath == "" {
		return nil
	}

	opts := make([]stdoutmetric.Option, 0)
	opts = append(opts, stdoutmetric.WithPrettyPrint())
	opts = append(opts, stdoutmetric.WithoutTimestamps())

	f, err := os.OpenFile(c.Exporters.Logging.MetricFilePath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	opts = append(opts, stdoutmetric.WithWriter(f))

	exp2, err := stdoutmetric.New(opts...)
	if err != nil {
		return err
	}
	// test logging

	provider := sdkmetric.NewMeterProvider(
		// https://github.com/open-telemetry/opentelemetry-go/issues/3720
		sdkmetric.WithReader(exp1),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp2)),
		sdkmetric.WithResource(res),
	)

	otel.SetMeterProvider(provider)

	meter := provider.Meter("app_or_package_name_prometheus")
	counter, _ := meter.Int64Counter(
		"grpc_kit.prometheus.demo.counter_name",
		apimetric.WithUnit("1"),
		apimetric.WithDescription("counter description"),
	)

	go func() {
		for {
			counter.Add(ctx, 1)
			time.Sleep(10 * time.Second)
		}
	}()

	return nil
}

func (c *ObservablesConfig) initExportOTLPGRPCMetric(ctx context.Context, res *resource.Resource) error {
	exp, err := otlpmetricgrpc.New(
		context.TODO(),
		// otlpmetricgrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")),
		otlpmetricgrpc.WithInsecure(),
		otlpmetricgrpc.WithEndpoint("ap-guangzhou.apm.tencentcs.com:4317"),
		otlpmetricgrpc.WithHeaders(c.Exporters.OTLPGRPC.Headers))

	if err != nil {
		return err
	}

	reader := sdkmetric.NewPeriodicReader(
		exp,
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
		apimetric.WithUnit("1"),
		apimetric.WithDescription("counter description"),
	)

	go func() {
		for {
			counter.Add(ctx, 1)
			time.Sleep(10 * time.Second)
		}
	}()

	return nil
}

func (c *ObservablesConfig) initExportLoggingMetric(ctx context.Context) error {
	if !c.Enable {
		return nil
	}
	if c.Exporters == nil || c.Exporters.Logging == nil || c.Exporters.Logging.MetricFilePath == "" {
		return nil
	}

	opts := make([]stdoutmetric.Option, 0)
	opts = append(opts, stdoutmetric.WithPrettyPrint())
	opts = append(opts, stdoutmetric.WithoutTimestamps())

	f, err := os.OpenFile(c.Exporters.Logging.MetricFilePath, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	opts = append(opts, stdoutmetric.WithWriter(f))

	exp, err := stdoutmetric.New(opts...)
	if err != nil {
		return err
	}

	/*
		exp2, err := otelprometheus.New(
			// 使用自定义的 prometheus registery 实例
			otelprometheus.WithRegisterer(c.promRegistry),
			// 避免对每个指标添加额外的 otel_scope_info 标签
			otelprometheus.WithoutScopeInfo(),
		)
	*/

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(exp),
		),
	)

	// otel.SetMeterProvider(provider)

	meter := provider.Meter("app_or_package_name_file")
	counter, _ := meter.Int64Counter(
		"grpc_kit.file.demo.counter_name",
		apimetric.WithUnit("1"),
		apimetric.WithDescription("counter description"),
	)

	go func() {
		for {
			counter.Add(ctx, 1)
			time.Sleep(10 * time.Second)
		}
	}()

	return nil
}

func (c *ObservablesConfig) initExportOTLPGRPC(ctx context.Context) error {
	if !c.Enable {
		return nil
	}
	if c.Exporters == nil || c.Exporters.OTLPGRPC == nil {
		return nil
	}

	tmps := strings.Split(c.Exporters.OTLPGRPC.Endpoint, "//")
	if len(tmps) != 2 {
		return fmt.Errorf("opentracing exporter otlp grpc endpoint error")
	}

	opts := make([]otlptracegrpc.Option, 0)
	if strings.HasPrefix(tmps[0], "https") {
		opts = append(opts, otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")))
	} else {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	opts = append(opts, otlptracegrpc.WithHeaders(c.Exporters.OTLPGRPC.Headers))
	opts = append(opts, otlptracegrpc.WithEndpoint(tmps[1]))

	client := otlptracegrpc.NewClient(opts...)
	exp, err := otlptrace.New(ctx, client)
	if err != nil {
		return err
	}

	bsp := sdktrace.NewBatchSpanProcessor(exp)
	c.tracer.RegisterSpanProcessor(bsp)

	return nil
}

func (c *ObservablesConfig) initExportOTLPHTTP(ctx context.Context) error {
	if !c.Enable {
		return nil
	}
	if c.Exporters == nil || c.Exporters.OTLPHTTP == nil {
		return nil
	}

	tmps := strings.Split(c.Exporters.OTLPHTTP.Endpoint, "//")
	if len(tmps) != 2 {
		return fmt.Errorf("opentracing exporter otlp http endpoint error")
	}

	trurl := c.Exporters.OTLPHTTP.TracesURLPath
	if trurl == "" {
		trurl = "/v1/traces"
	}

	opts := make([]otlptracehttp.Option, 0)
	if strings.HasPrefix(tmps[0], "https") {
	} else {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	opts = append(opts, otlptracehttp.WithHeaders(c.Exporters.OTLPHTTP.Headers))
	opts = append(opts, otlptracehttp.WithEndpoint(tmps[1]))
	opts = append(opts, otlptracehttp.WithURLPath(trurl))

	client := otlptracehttp.NewClient(opts...)
	otlptracehttp.WithCompression(1)

	exp, err := otlptrace.New(ctx, client)
	if err != nil {
		return err
	}

	bsp := sdktrace.NewBatchSpanProcessor(exp)
	c.tracer.RegisterSpanProcessor(bsp)

	return nil
}

func (c *ObservablesConfig) initExportLogging(ctx context.Context) error {
	if !c.Enable {
		return nil
	}
	if c.Exporters == nil || c.Exporters.Logging == nil || c.Exporters.Logging.FilePath == "" {
		return nil
	}

	opts := make([]stdouttrace.Option, 0)
	if c.Exporters.Logging.PrettyPrint {
		opts = append(opts, stdouttrace.WithPrettyPrint())
	}
	if c.Exporters.Logging.FilePath != "" && c.Exporters.Logging.FilePath != "stdout" {
		f, err := os.OpenFile(c.Exporters.Logging.FilePath, os.O_RDWR|os.O_CREATE, 0755)
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
	c.tracer.RegisterSpanProcessor(bsp)

	return nil
}

func (c *ObservablesConfig) calcRequestID(ctx context.Context) string {
	requestID := "0123456789abcdef0123456789abcdef"

	spanCtx := trace.SpanContextFromContext(ctx)
	if spanCtx.HasTraceID() {
		requestID = spanCtx.TraceID().String()
	}

	return requestID
}

// 判断是否记录 http 请求体
func (c *ObservablesConfig) hasRecordLogFieldsHTTPRequest() bool {
	if c.Telemetry == nil || c.Telemetry.Traces == nil {
		return false
	}

	return c.Telemetry.Traces.LogFields.HTTPRequest
}

// 判断是否记录 http 响应体
func (c *ObservablesConfig) hasRecordLogFieldsHTTPResponse() bool {
	if c.Telemetry == nil || c.Telemetry.Traces == nil {
		return false
	}

	return c.Telemetry.Traces.LogFields.HTTPResponse
}

// httpTracingEnableFilter 哪些 http 请求开启链路跟踪
func (c *ObservablesConfig) httpTracingEnableFilter(r *http.Request) bool {
	switch r.URL.Path {
	case "/healthz", "/ping", "/metrics", "/version", "/favicon.ico":
		return false
	}

	if c.Telemetry == nil || c.Telemetry.Traces == nil {
		return true
	}

	// 是否存在指定的跟踪接口
	for _, v := range c.Telemetry.Traces.Filters {
		if v.URLPath != "" && v.URLPath == r.URL.Path {
			if v.Method == "" {
				return false
			} else if strings.ToLower(v.Method) == strings.ToLower(r.Method) {
				return false
			}
		}

		if v.Method != "" && v.URLPath == "" {
			if strings.ToLower(v.Method) == strings.ToLower(r.Method) {
				return false
			}
		}
	}

	return true
}

// grpcTracingEnableFilter 哪些 http 请求开启链路跟踪
func (c *ObservablesConfig) grpcTracingEnableFilter(i *otelgrpc.InterceptorInfo) bool {
	if i.UnaryServerInfo == nil {
		return false
	}

	grpcMethod := path.Base(i.UnaryServerInfo.FullMethod)

	// 忽略内置的健康检查接口
	switch grpcMethod {
	case "HealthCheck":
		return false
	}

	if c.Telemetry != nil && c.Telemetry.Traces != nil {
		for _, v := range c.Telemetry.Traces.Filters {
			if v.URLPath == "" && v.Method != "" {
				if v.Method == grpcMethod {
					return false
				}
			}
		}
	}

	return true
}

// grpcPanicRecoveryHandler 用于 grpc 产生 panic 时候记录堆栈信息
func (c *ObservablesConfig) grpcPanicRecoveryHandler(ctx context.Context, p any) error {
	span := trace.SpanFromContext(ctx)
	if span != nil && span.IsRecording() {
		span.AddEvent("error",
			trace.WithAttributes(attribute.String("event", "error")),
			trace.WithAttributes(attribute.String("stack", string(debug.Stack()))),
		)
	}

	return status.Errorf(codes.Internal, "%s", p)
}
