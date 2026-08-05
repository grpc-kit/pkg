package cfg

import (
	"context"
	"testing"
	"time"

	"github.com/spf13/viper"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	apimetric "go.opentelemetry.io/otel/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestObservables(t *testing.T) {
	config := newObservablesTestConfig(t)
	config.Observables.defaultValues()
	t.Run("testObservablesDefaultValues", func(t *testing.T) {
		testObservablesDefaultValues(t, config.Observables)
	})

	// Exporter defaults are verified above. Network exporters are disabled only
	// for this test instance so the suite never depends on a local collector.
	disabled := false
	config.Observables.Telemetry.Traces.Exporters.OTLP = &disabled
	config.Observables.Telemetry.Traces.Exporters.OTLPHTTP = &disabled
	config.Observables.Telemetry.Traces.Exporters.Logging = &disabled
	previousTracerProvider := otel.GetTracerProvider()
	previousMeterProvider := otel.GetMeterProvider()
	if err := config.initObservables(); err != nil {
		t.Fatal(err)
	}

	spanExporter := tracetest.NewInMemoryExporter()
	config.Observables.tracer.RegisterSpanProcessor(sdktrace.NewSimpleSpanProcessor(spanExporter))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := config.Observables.shutdown(ctx); err != nil {
			t.Errorf("shutdown observables: %v", err)
		}
		otel.SetTracerProvider(previousTracerProvider)
		otel.SetMeterProvider(previousMeterProvider)
	})

	t.Run("testObservablesTracer", func(t *testing.T) {
		testObservablesTracer(t, config.Observables, spanExporter)
	})
	t.Run("testObservablesMeter", func(t *testing.T) {
		testObservablesMeter(t, config.Observables)
	})
}

func newObservablesTestConfig(t *testing.T) *LocalConfig {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetConfigFile("app-sample.yaml")
	if err := v.ReadInConfig(); err != nil {
		t.Fatal(err)
	}
	config, err := New(v)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

// testObservablesDefaultValues 用于服务初始化默认值的判断
func testObservablesDefaultValues(t *testing.T, o *ObservablesConfig) {
	if o == nil {
		t.Errorf("observables config is nil")
	}

	if o.Enable == nil || *o.Enable != true {
		t.Errorf("`observables.enable` not default value")
	}

	if o.Telemetry == nil || o.Telemetry.Metrics == nil {
		t.Errorf("`observables.telemetry.metrics` is nil")
	}

	if o.Telemetry == nil || o.Telemetry.Traces == nil {
		t.Errorf("`observables.telemetry.traces` is nil")
	}

	if o.Telemetry.Metrics.PushInterval != 60 {
		t.Errorf("`observables.telemetry.metrics.push_interval` not default value")
	}

	if *o.Telemetry.Metrics.Exporters.OTLP != false ||
		*o.Telemetry.Metrics.Exporters.OTLPHTTP != false ||
		*o.Telemetry.Metrics.Exporters.Prometheus != true ||
		*o.Telemetry.Metrics.Exporters.Logging != true {
		t.Errorf("`observables.telemetry.metrics.exporters` not default value")
	}

	if *o.Telemetry.Traces.SampleRatio != 1 {
		t.Errorf("`observables.telemetry.traces.sample_ratio` not default value")
	}

	if *o.Telemetry.Traces.Exporters.OTLP != true ||
		*o.Telemetry.Traces.Exporters.OTLPHTTP != true ||
		*o.Telemetry.Traces.Exporters.Prometheus != false ||
		*o.Telemetry.Traces.Exporters.Logging != true {
		t.Errorf("`observables.telemetry.traces.exporters` not default value")
	}

	if o.Exporters == nil {
		t.Errorf("`observables.exporters` is nil")
	}

	if o.Exporters.Prometheus == nil || o.Exporters.Prometheus.MetricsURLPath != "/metrics" {
		t.Errorf("`observables.exporters.prometheus.metrics_url_path` not default value")
	}

	if o.Exporters.Logging == nil {
		t.Errorf("`observables.exporters.logging` is nil")
	}

	if o.Exporters.Logging.PrettyPrint != true && o.Exporters.Logging.MetricsFilePath != "/tmp/metrics.log" {
		t.Errorf("`observables.exporters.logging.metrics_file_path` not default value")
	}

	if o.Exporters.Logging.PrettyPrint != true && o.Exporters.Logging.TracesFilePath != "/tmp/traces.log" {
		t.Errorf("`observables.exporters.logging.traces_file_path` not default value")
	}
}

// testObservablesTracer 使用内存 exporter 验证链路，不依赖外部 OTLP collector。
func testObservablesTracer(t *testing.T, observables *ObservablesConfig, exporter *tracetest.InMemoryExporter) {
	ctx := context.TODO()
	packageName := "github.com/grpc-kit/pkg"

	tr := otel.Tracer(packageName)

	rootCtx, rootSpan := tr.Start(ctx, "RootSpan")
	rootSpan.AddEvent("custom", trace.WithAttributes(
		attribute.String("custom.log1", "value1"),
	))

	rpcSpan1Ctx, rpcSpan1 := tr.Start(rootCtx, "RPCSpan1")
	_, rpcSpan1Child1 := tr.Start(rpcSpan1Ctx, "RPCSpan1-Child1")
	_, rpcSpan1Child2 := tr.Start(rpcSpan1Ctx, "RPCSpan1-Child2")

	databaseCtx, databaseSpan := tr.Start(rootCtx, "Database")
	_, mysqlSpan := tr.Start(databaseCtx, "Query MySQL")
	mysqlSpan.AddEvent("mysql", trace.WithAttributes(
		attribute.String("db.instance", "mysql-1"),
		attribute.String("db.statement", "SELECT * FROM users"),
	))

	_, redisSpan := tr.Start(databaseCtx, "Query Redis")
	redisSpan.AddEvent("redis", trace.WithAttributes(
		attribute.String("db.instance", "redis-1"),
		attribute.String("db.statement", "GET name"),
	))

	rpcSpan1Child1.End()
	rpcSpan1Child2.End()

	mysqlSpan.End()
	redisSpan.End()
	databaseSpan.End()

	rpcSpan1.End()
	rootSpan.End()

	// 关闭前需强制刷新下内存数据，否则会丢失来不及上报
	// 使用框架时无需处理，在服务关闭前会自动刷新
	if err := observables.tracer.ForceFlush(ctx); err != nil {
		t.Fatal(err)
	}
	spans := exporter.GetSpans()
	if len(spans) != 7 {
		t.Fatalf("exported spans = %d, want 7", len(spans))
	}
}

// testObservablesMeter 用于性能数据上报测试
func testObservablesMeter(t *testing.T, observables *ObservablesConfig) {
	ctx := context.TODO()
	packageName := "github.com/grpc-kit/pkg"

	mt := otel.Meter(packageName)

	opts := apimetric.WithAttributes(
		attribute.Key("key1").String("val1"),
		attribute.Key("key2").String("val2"),
	)

	counter, err := mt.Float64Counter("hello.go.testname",
		apimetric.WithDescription("a demo test"))

	if err != nil {
		t.Error(err)
	}

	counter.Add(ctx, 5, opts)

	if err := observables.meter.ForceFlush(ctx); err != nil {
		t.Error(err)
	}
}
