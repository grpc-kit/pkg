package cfg

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime/debug"
	"strings"
	"time"

	"github.com/grpc-kit/pkg/vars"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otelprometheus "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// ObservablesConfig 用于客观性配置
type ObservablesConfig struct {
	tracer       *sdktrace.TracerProvider
	promRegistry *prometheus.Registry

	// 全局是否启动可观测性
	Enable bool `mapstructure:"enable"`

	// 首次初始化后配置默认值
	Telemetry *TelemetryConfig `mapstructure:"telemetry"`

	// 可观测性数据上报服务地址
	Exporters *struct {
		OTLPGRPC   *OTLPGRPCConfig `mapstructure:"otlp"`
		OTLPHTTP   *OTLPHTTPConfig `mapstructure:"otlphttp"`
		Prometheus *struct {
			MetricURLPath string `mapstructure:"metric_url_path"`
		}
		Logging *struct {
			MetricFilePath string `mapstructure:"metric_file_path"`
			TraceFilePath  string `mapstructure:"trace_file_path"`
			PrettyPrint    bool   `mapstructure:"pretty_print"`
		} `mapstructure:"logging"`
	} `mapstructure:"exporters"`
}

// OTLPHTTPConfig xx
type OTLPHTTPConfig struct {
	// The target URL to send data to (e.g.: http://some.url:9411).
	Endpoint      string            `mapstructure:"endpoint"`
	Headers       map[string]string `mapstructure:"headers"`
	TraceURLPath  string            `mapstructure:"trace_url_path"`
	MetricURLPath string            `mapstructure:"metric_url_path"`
}

// OTLPGRPCConfig xx
type OTLPGRPCConfig struct {
	// The target URL to send data to (e.g.: http://some.url:9411).
	Endpoint string            `mapstructure:"endpoint"`
	Headers  map[string]string `mapstructure:"headers"`
}

// TelemetryConfig xx
type TelemetryConfig struct {
	Metrics *TelemetryMetric `mapstructure:"metrics"`
	Traces  *TelemetryTrace  `mapstructure:"traces"`
}

// TelemetryMetric 性能指标个性配置
type TelemetryMetric struct {
	// 为所有暴露的指标添加前缀
	Namespace string
	// 是否启用 Exporters 配置下的 otel otelhttp logging prometheus
	Exporters ExporterEnable `mapstructure:"exporter_enable"`
}

// TelemetryTrace 链路跟踪个性配置
type TelemetryTrace struct {
	// 给定一个 0 至 1 之间的分数决定采样频率
	SampleRatio float64 `mapstructure:"sample_ratio"`

	// 是否启用 Exporters 配置下的 otel otelhttp logging
	Exporters ExporterEnable `mapstructure:"exporter_enable"`

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
}

// ExporterEnable 配置是否启用特定 exporter
type ExporterEnable struct {
	OTLP       *bool `mapstructure:"otlp"`
	OTLPHTTP   *bool `mapstructure:"otlphttp"`
	Logging    *bool `mapstructure:"logging"`
	Prometheus *bool `mapstructure:"prometheus"`
}

// InitObservables 初始化可观测性配置
func (c *LocalConfig) InitObservables() (interface{}, error) {
	if c.Observables == nil {
		c.Observables = &ObservablesConfig{
			Enable: false,
		}
	}

	// 植入默认值
	c.Observables.defaultValues()

	if !c.Observables.Enable {
		return nil, nil
	}

	ctx := context.Background()
	serviceName := c.GetServiceName()
	if err := c.Observables.initMetricsExporter(ctx, serviceName); err != nil {
		return nil, err
	}
	if err := c.Observables.initTracesExporter(ctx, serviceName); err != nil {
		return nil, err
	}

	return nil, nil
}

// defaultValues 初始化默认值
func (c *ObservablesConfig) defaultValues() {
	// default values
	var enableVal = true
	var disalbeVal = false

	defaultMetric := &TelemetryMetric{
		Exporters: ExporterEnable{
			OTLP:       &disalbeVal,
			OTLPHTTP:   &disalbeVal,
			Logging:    &enableVal,
			Prometheus: &enableVal,
		},
	}
	defaultTrace := &TelemetryTrace{
		Exporters: ExporterEnable{
			OTLP:       &enableVal,
			OTLPHTTP:   &enableVal,
			Logging:    &enableVal,
			Prometheus: &disalbeVal,
		},
	}

	if c.Telemetry == nil {
		c.Telemetry = &TelemetryConfig{
			Metrics: defaultMetric,
			Traces:  defaultTrace,
		}
	}

	// 客户端自定义了 telemetry 配置
	if c.Telemetry.Metrics == nil {
		c.Telemetry.Metrics = defaultMetric
	} else {
		if c.Telemetry.Metrics.Exporters.OTLP == nil {
			c.Telemetry.Metrics.Exporters.OTLP = &disalbeVal
		}
		if c.Telemetry.Metrics.Exporters.OTLPHTTP == nil {
			c.Telemetry.Metrics.Exporters.OTLPHTTP = &disalbeVal
		}
		if c.Telemetry.Metrics.Exporters.Logging == nil {
			c.Telemetry.Metrics.Exporters.Logging = &enableVal
		}
		if c.Telemetry.Metrics.Exporters.Prometheus == nil {
			c.Telemetry.Metrics.Exporters.Prometheus = &enableVal
		}
	}

	if c.Telemetry.Traces == nil {
		c.Telemetry.Traces = defaultTrace
	} else {
		if c.Telemetry.Traces.Exporters.OTLP == nil {
			c.Telemetry.Traces.Exporters.OTLP = &enableVal
		}
		if c.Telemetry.Traces.Exporters.OTLPHTTP == nil {
			c.Telemetry.Traces.Exporters.OTLPHTTP = &enableVal
		}
		if c.Telemetry.Traces.Exporters.Logging == nil {
			c.Telemetry.Traces.Exporters.Logging = &enableVal
		}
		if c.Telemetry.Traces.Exporters.Prometheus == nil {
			c.Telemetry.Traces.Exporters.Prometheus = &disalbeVal
		}
	}
}

// shutdown 关闭前刷新数据并释放资源
func (c *ObservablesConfig) shutdown(ctx context.Context) error {
	if err := c.tracer.ForceFlush(ctx); err != nil {
		return err
	}
	if err := c.tracer.Shutdown(ctx); err != nil {
		return err
	}
	return nil
}

// initMetricsExporter 初始化 metrics exporter 相关
func (c *ObservablesConfig) initMetricsExporter(ctx context.Context, serviceName string) error {
	// 初始化 prometheus registery 实例
	reg := prometheus.NewRegistry()
	prometheus.MustRegister(reg)

	// 添加 go_build_info、go_gc_x、go_memstats_x 几个 go 应用指标
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewBuildInfoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	c.promRegistry = reg

	// 避免使用 WithFromEnv 以防止不必要的信息泄漏，如 token 保留到指标
	res, err := resource.New(ctx,
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithProcessOwner(),
		resource.WithOSType(),
		resource.WithAttributes(
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(vars.ReleaseVersion),
		),
	)
	if err != nil {
		return err
	}

	mpOpts := make([]sdkmetric.Option, 0)
	mpOpts = append(mpOpts, sdkmetric.WithResource(res))

	// 添加多个 reader
	// https://github.com/open-telemetry/opentelemetry-go/issues/3720

	if c.hasMetricsEnableExporterPrometheus() {
		var exp *otelprometheus.Exporter

		exp, err = otelprometheus.New(
			// 使用自定义的 prometheus registery 实例
			otelprometheus.WithRegisterer(c.promRegistry),
			// 避免对每个指标添加额外的 otel_scope_info 标签
			otelprometheus.WithoutScopeInfo(),
		)
		if err != nil {
			return err
		}

		mpOpts = append(mpOpts, sdkmetric.WithReader(exp))
	}

	if c.hasMetricsEnableExporterLogging() {
		var out *os.File
		out, err = os.OpenFile(c.Exporters.Logging.MetricFilePath, os.O_RDWR|os.O_CREATE, 0755)
		if err != nil {
			return err
		}

		var exp sdkmetric.Exporter
		exp, err = stdoutmetric.New(
			stdoutmetric.WithPrettyPrint(),
			stdoutmetric.WithoutTimestamps(),
			stdoutmetric.WithWriter(out))
		if err != nil {
			return err
		}

		mpOpts = append(mpOpts, sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)))
	}

	if c.hasMetricsEnableExporterOTLP() {
		u, err := url.Parse(c.Exporters.OTLPGRPC.Endpoint)
		if err != nil {
			return err
		}

		exOpts := make([]otlpmetricgrpc.Option, 0)
		if u.Scheme == "https" {
			exOpts = append(exOpts, otlpmetricgrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")))
		} else {
			exOpts = append(exOpts, otlpmetricgrpc.WithInsecure())
		}
		exOpts = append(exOpts, otlpmetricgrpc.WithEndpoint(u.Host))

		headers := c.Exporters.OTLPGRPC.Headers
		headers["user-agent"] = fmt.Sprintf("%v/%v", vars.Appname, vars.ReleaseVersion)
		exOpts = append(exOpts, otlpmetricgrpc.WithHeaders(headers))

		var exp sdkmetric.Exporter
		exp, err = otlpmetricgrpc.New(ctx, exOpts...)
		if err != nil {
			return err
		}

		reader := sdkmetric.NewPeriodicReader(exp,
			sdkmetric.WithInterval(15*time.Second),
		)
		mpOpts = append(mpOpts, sdkmetric.WithReader(reader))
	}

	if c.hasMetricsEnableExporterOTLPHTTP() {
		u, err := url.Parse(c.Exporters.OTLPHTTP.Endpoint)
		if err != nil {
			return err
		}

		exOpts := make([]otlpmetrichttp.Option, 0)
		if u.Scheme == "https" {
			// TODO; 跳过 tls ca 验证
			exOpts = append(exOpts, otlpmetrichttp.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: true}))
		} else {
			exOpts = append(exOpts, otlpmetrichttp.WithInsecure())
		}
		exOpts = append(exOpts, otlpmetrichttp.WithEndpoint(u.Host))

		headers := c.Exporters.OTLPHTTP.Headers
		headers["user-agent"] = fmt.Sprintf("%v/%v", vars.Appname, vars.ReleaseVersion)
		exOpts = append(exOpts, otlpmetrichttp.WithHeaders(headers))

		if c.Exporters.OTLPHTTP.MetricURLPath != "" {
			exOpts = append(exOpts, otlpmetrichttp.WithURLPath(c.Exporters.OTLPHTTP.MetricURLPath))
		}

		var exp sdkmetric.Exporter
		exp, err = otlpmetrichttp.New(ctx, exOpts...)
		if err != nil {
			return err
		}

		reader := sdkmetric.NewPeriodicReader(exp,
			sdkmetric.WithInterval(15*time.Second),
		)
		mpOpts = append(mpOpts, sdkmetric.WithReader(reader))
	}

	provider := sdkmetric.NewMeterProvider(mpOpts...)
	otel.SetMeterProvider(provider)

	return nil
}

// initTracesExporter 初始化 traces exporter 相关
func (c *ObservablesConfig) initTracesExporter(ctx context.Context, serviceName string) error {
	hostName, err := os.Hostname()
	if err != nil || hostName == "" {
		hostName = "unknow"
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithProcessOwner(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithOSType(),
		resource.WithProcessExecutablePath(),
		resource.WithAttributes(
			// 在可观测链路 OpenTelemetry 版后端显示的服务名称。
			semconv.ServiceName(serviceName),
			// 在可观测链路 OpenTelemetry 版后端显示的主机名称。
			semconv.HostName(hostName),
			semconv.ServiceVersion(vars.ReleaseVersion),
		),
	)

	// 控制采样频率
	sampleRatio := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.2))
	if c.Telemetry != nil {
		if c.Telemetry.Traces != nil {
			ratio := c.Telemetry.Traces.SampleRatio
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
	c.tracer = tracerProvider

	if c.hasTracesEnableExporterOTLP() {
		u, err := url.Parse(c.Exporters.OTLPGRPC.Endpoint)
		if err != nil {
			return err
		}

		exOpts := make([]otlptracegrpc.Option, 0)
		if u.Scheme == "https" {
			exOpts = append(exOpts, otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")))
		} else {
			exOpts = append(exOpts, otlptracegrpc.WithInsecure())
		}

		exOpts = append(exOpts, otlptracegrpc.WithHeaders(c.Exporters.OTLPGRPC.Headers))
		exOpts = append(exOpts, otlptracegrpc.WithEndpoint(u.Host))

		client := otlptracegrpc.NewClient(exOpts...)
		exp, err := otlptrace.New(ctx, client)
		if err != nil {
			return err
		}

		bsp := sdktrace.NewBatchSpanProcessor(exp)
		c.tracer.RegisterSpanProcessor(bsp)
	}

	if c.hasTracesEnableExporterOTLPHTTP() {
		u, err := url.Parse(c.Exporters.OTLPHTTP.Endpoint)
		if err != nil {
			return err
		}

		exOpts := make([]otlptracehttp.Option, 0)
		if u.Scheme == "https" {
			exOpts = append(exOpts, otlptracehttp.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: true}))
		} else {
			exOpts = append(exOpts, otlptracehttp.WithInsecure())
		}

		headers := c.Exporters.OTLPHTTP.Headers
		headers["user-agent"] = fmt.Sprintf("%v/%v", vars.Appname, vars.ReleaseVersion)
		exOpts = append(exOpts, otlptracehttp.WithHeaders(headers))

		exOpts = append(exOpts, otlptracehttp.WithEndpoint(u.Host))
		if c.Exporters.OTLPHTTP.TraceURLPath != "" {
			exOpts = append(exOpts, otlptracehttp.WithURLPath(c.Exporters.OTLPHTTP.TraceURLPath))
		}

		client := otlptracehttp.NewClient(exOpts...)
		otlptracehttp.WithCompression(1)

		exp, err := otlptrace.New(ctx, client)
		if err != nil {
			return err
		}

		bsp := sdktrace.NewBatchSpanProcessor(exp)
		c.tracer.RegisterSpanProcessor(bsp)
	}

	if c.hasTracesEnableExporterOTLPLogging() {
		opts := make([]stdouttrace.Option, 0)
		if c.Exporters.Logging.PrettyPrint {
			opts = append(opts, stdouttrace.WithPrettyPrint())
		}
		if c.Exporters.Logging.TraceFilePath != "" && c.Exporters.Logging.TraceFilePath != "stdout" {
			f, err := os.OpenFile(c.Exporters.Logging.TraceFilePath, os.O_RDWR|os.O_CREATE, 0755)
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
	}

	otel.SetTextMapPropagator(propagation.TraceContext{})
	otel.SetTracerProvider(tracerProvider)

	return nil
}

// calcRequestID 计算 trace id
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

// hasTracesEnableExporterOTLP 是否启用 otlp 上报 traces 数据
func (c *ObservablesConfig) hasTracesEnableExporterOTLP() bool {
	if c.Exporters == nil || c.Exporters.OTLPGRPC == nil || c.Exporters.OTLPGRPC.Endpoint == "" {
		return false
	}

	return *(c.Telemetry.Traces.Exporters.OTLP)
}

// hasTracesEnableExporterOTLPHTTP 是否启用 otlphttp 上报 traces 数据
func (c *ObservablesConfig) hasTracesEnableExporterOTLPHTTP() bool {
	if c.Exporters == nil || c.Exporters.OTLPHTTP == nil || c.Exporters.OTLPHTTP.Endpoint == "" {
		return false
	}

	return *(c.Telemetry.Traces.Exporters.OTLPHTTP)
}

// hasTracesEnableExporterOTLPLogging 是否启用 logging 记录 traces 数据
func (c *ObservablesConfig) hasTracesEnableExporterOTLPLogging() bool {
	if c.Exporters == nil || c.Exporters.Logging == nil || c.Exporters.Logging.TraceFilePath == "" {
		return false
	}

	return *(c.Telemetry.Traces.Exporters.Logging)
}

// hasMetricsEnableExporterOTLP 是否启用 otlp 上报 metrics 数据
func (c *ObservablesConfig) hasMetricsEnableExporterOTLP() bool {
	if c.Exporters == nil || c.Exporters.OTLPGRPC == nil || c.Exporters.OTLPGRPC.Endpoint == "" {
		return false
	}

	return *(c.Telemetry.Metrics.Exporters.OTLP)
}

// hasMetricsEnableExporterOTLPHTTP 是否启用 otlphttp 上报 metrics 数据
func (c *ObservablesConfig) hasMetricsEnableExporterOTLPHTTP() bool {
	if c.Exporters == nil || c.Exporters.OTLPHTTP == nil || c.Exporters.OTLPHTTP.Endpoint == "" {
		return false
	}

	return *(c.Telemetry.Metrics.Exporters.OTLPHTTP)
}

// hasMetricsEnableExporterPrometheus 是否启用 promhttp 输出指标地址
func (c *ObservablesConfig) hasMetricsEnableExporterPrometheus() bool {
	return *(c.Telemetry.Metrics.Exporters.Prometheus)
}

// hasMetricsEnableExporterLogging 是否启用 logging 记录 metrics 数据
func (c *ObservablesConfig) hasMetricsEnableExporterLogging() bool {
	if c.Exporters == nil || c.Exporters.Logging == nil || c.Exporters.Logging.MetricFilePath == "" {
		return false
	}

	return *(c.Telemetry.Metrics.Exporters.Logging)
}

// prometheusExporterHTTP 用于注册性能指标数据至 http 上，如：/metrics
func (c *ObservablesConfig) prometheusExporterHTTP(hmux *http.ServeMux) {
	if !c.hasMetricsEnableExporterPrometheus() {
		return
	}

	metricURL := "/metrics"
	if c.Exporters != nil {
		if c.Exporters.Prometheus != nil && c.Exporters.Prometheus.MetricURLPath != "" {
			metricURL = c.Exporters.Prometheus.MetricURLPath
		}
	}

	hmux.Handle(metricURL, promhttp.InstrumentMetricHandler(
		c.promRegistry,
		promhttp.HandlerFor(
			c.promRegistry,
			promhttp.HandlerOpts{
				Registry:          c.promRegistry,
				EnableOpenMetrics: true,
			})),
	)
}
