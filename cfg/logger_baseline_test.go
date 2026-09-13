package cfg

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestInitDebuggerLevelBaseline(t *testing.T) {
	tests := []struct {
		name     string
		debugger *DebuggerConfig
		want     logrus.Level
	}{
		{name: "nil debugger", want: logrus.InfoLevel},
		{name: "empty level", debugger: &DebuggerConfig{}, want: logrus.ErrorLevel},
		{name: "panic", debugger: &DebuggerConfig{LogLevel: "panic"}, want: logrus.PanicLevel},
		{name: "fatal", debugger: &DebuggerConfig{LogLevel: "fatal"}, want: logrus.FatalLevel},
		{name: "error", debugger: &DebuggerConfig{LogLevel: "error"}, want: logrus.ErrorLevel},
		{name: "warn", debugger: &DebuggerConfig{LogLevel: "warn"}, want: logrus.WarnLevel},
		{name: "info", debugger: &DebuggerConfig{LogLevel: "info"}, want: logrus.InfoLevel},
		{name: "debug", debugger: &DebuggerConfig{LogLevel: "debug"}, want: logrus.DebugLevel},
		{name: "documented trace falls back", debugger: &DebuggerConfig{LogLevel: "trace"}, want: logrus.WarnLevel},
		{name: "unknown falls back", debugger: &DebuggerConfig{LogLevel: "invalid"}, want: logrus.WarnLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preserveStandardLogger(t)

			config := loggerBaselineConfig(tt.debugger)
			if err := config.initDebugger(); err != nil {
				t.Fatalf("initDebugger() error = %v", err)
			}
			if got := config.GetLogger().Logger.GetLevel(); got != tt.want {
				t.Errorf("logger level = %v, want %v", got, tt.want)
			}
			if config.GetLogger().Logger.Out != os.Stdout {
				t.Errorf("logger output = %v, want os.Stdout", config.GetLogger().Logger.Out)
			}
			if got := config.GetLogger().Data["service_name"]; got != "service.api" {
				t.Errorf("service_name = %v, want service.api", got)
			}
		})
	}
}

func TestInitDebuggerFormatBaseline(t *testing.T) {
	tests := []struct {
		name       string
		format     string
		wantJSON   bool
		wantColors bool
	}{
		{name: "empty uses text without colors", wantColors: false},
		{name: "text disables colors", format: "text", wantColors: false},
		{name: "json", format: "json", wantJSON: true},
		{name: "unknown uses default text formatter", format: "invalid", wantColors: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preserveStandardLogger(t)

			config := loggerBaselineConfig(&DebuggerConfig{LogLevel: "info", LogFormat: tt.format})
			if err := config.initDebugger(); err != nil {
				t.Fatalf("initDebugger() error = %v", err)
			}

			switch formatter := config.GetLogger().Logger.Formatter.(type) {
			case *logrus.JSONFormatter:
				if !tt.wantJSON {
					t.Errorf("formatter = JSONFormatter, want text")
				}
			case *logrus.TextFormatter:
				if tt.wantJSON {
					t.Errorf("formatter = TextFormatter, want JSON")
				}
				if got := !formatter.DisableColors; got != tt.wantColors {
					t.Errorf("colors enabled = %v, want %v", got, tt.wantColors)
				}
			default:
				t.Errorf("formatter type = %T, want logrus JSONFormatter or TextFormatter", formatter)
			}
		})
	}
}

func TestInitDebuggerJSONOutputBaseline(t *testing.T) {
	preserveStandardLogger(t)

	config := loggerBaselineConfig(&DebuggerConfig{LogLevel: "debug", LogFormat: "json"})
	if err := config.initDebugger(); err != nil {
		t.Fatalf("initDebugger() error = %v", err)
	}

	var output bytes.Buffer
	config.GetLogger().Logger.SetOutput(&output)
	config.GetLogger().WithField("request_id", "request-test").Info("baseline message")

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("unmarshal log output %q: %v", output.String(), err)
	}
	for key, want := range map[string]string{
		"level":        "info",
		"msg":          "baseline message",
		"request_id":   "request-test",
		"service_name": "service.api",
	} {
		if got := record[key]; got != want {
			t.Errorf("record[%q] = %v, want %q", key, got, want)
		}
	}
	timestamp, ok := record["time"].(string)
	if !ok {
		t.Fatalf("record[time] = %T, want string", record["time"])
	}
	if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
		t.Errorf("record[time] = %q, want RFC3339Nano: %v", timestamp, err)
	}
}

func TestInitDebuggerTextOutputBaseline(t *testing.T) {
	preserveStandardLogger(t)

	config := loggerBaselineConfig(&DebuggerConfig{LogLevel: "debug", LogFormat: "text"})
	if err := config.initDebugger(); err != nil {
		t.Fatalf("initDebugger() error = %v", err)
	}

	var output bytes.Buffer
	config.GetLogger().Logger.SetOutput(&output)
	config.GetLogger().WithField("request_id", "request-test").Info("baseline message")

	for _, want := range []string{
		"level=info",
		`msg="baseline message"`,
		"request_id=request-test",
		"service_name=service.api",
	} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("log output %q does not contain %q", output.String(), want)
		}
	}
}

func BenchmarkLogrusJSONBaseline(b *testing.B) {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.SetOutput(io.Discard)
	logger.SetLevel(logrus.InfoLevel)
	entry := logger.WithField("service_name", "service.api")

	b.ReportAllocs()
	for b.Loop() {
		entry.WithField("request_id", "request-test").Info("baseline message")
	}
}

func BenchmarkLogrusDisabledDebugBaseline(b *testing.B) {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	logger.SetLevel(logrus.InfoLevel)
	entry := logger.WithField("service_name", "service.api")

	b.ReportAllocs()
	for b.Loop() {
		entry.Debug("disabled baseline message")
	}
}

func loggerBaselineConfig(debugger *DebuggerConfig) *LocalConfig {
	return &LocalConfig{
		Services: &ServicesConfig{
			ServiceCode: "service",
			APIEndpoint: "api",
		},
		Debugger: debugger,
	}
}

func preserveStandardLogger(t *testing.T) {
	t.Helper()

	logger := logrus.StandardLogger()
	level := logger.GetLevel()
	formatter := logger.Formatter
	output := logger.Out

	t.Cleanup(func() {
		logger.SetLevel(level)
		logger.SetFormatter(formatter)
		logger.SetOutput(output)
	})
}
