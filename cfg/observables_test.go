package cfg

import "testing"

func TestObservables(t *testing.T) {
	t.Run("testObservablesDefaultValues", testObservablesDefaultValues)
}

// testObservablesDefaultValues 用于服务初始化默认值的判断
func testObservablesDefaultValues(t *testing.T) {
	if err := lc.InitObservables(); err != nil {
		t.Error(err)
	}

	o := lc.Observables
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

	if *o.Telemetry.Metrics.Exporters.OTLP != false ||
		*o.Telemetry.Metrics.Exporters.OTLPHTTP != false ||
		*o.Telemetry.Metrics.Exporters.Prometheus != true ||
		*o.Telemetry.Metrics.Exporters.Logging != true {
		t.Errorf("`observables.telemetry.exporters` not default value")
	}

	if *o.Telemetry.Traces.Exporters.OTLP != true ||
		*o.Telemetry.Traces.Exporters.OTLPHTTP != true ||
		*o.Telemetry.Traces.Exporters.Prometheus != false ||
		*o.Telemetry.Traces.Exporters.Logging != true {
		t.Errorf("`observables.telemetry.exporters` not default value")
	}

	if o.Exporters == nil {
		t.Errorf("`observables.exporters` is nil")
	}

	if o.Exporters.Prometheus == nil || o.Exporters.Prometheus.MetricURLPath != "/metrics" {
		t.Errorf("`observables.exporters.prometheus.metric_url_path` not default value")
	}

	if o.Exporters.Logging == nil {
		t.Errorf("`observables.exporters.logging` is nil")
	}

	if o.Exporters.Logging.PrettyPrint != true && o.Exporters.Logging.MetricFilePath != "/tmp/metrics.log" {
		t.Errorf("`observables.exporters.logging.metric_file_path` not default value")
	}

	if o.Exporters.Logging.PrettyPrint != true && o.Exporters.Logging.TraceFilePath != "/tmp/traces.log" {
		t.Errorf("`observables.exporters.logging.trace_file_path` not default value")
	}
}
