package cfg

import (
	"context"
	"fmt"
	"os"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/sirupsen/logrus"
)

// InitDebugger 用于初始化日志实例
func (c *LocalConfig) InitDebugger() error {
	logger := logrus.WithFields(
		logrus.Fields{
			"service_name": c.GetServiceName(),
		})

	if c.Debugger == nil {
		c.Debugger = &DebuggerConfig{
			LogLevel:    "info",
			LogFormat:   "text",
			EnablePprof: false,
		}
	}

	logLevel := c.Debugger.LogLevel
	logFormat := c.Debugger.LogFormat

	if logLevel == "" {
		logLevel = "error"
	}
	if logFormat == "" {
		logFormat = "text"
	}

	switch logLevel {
	case "panic":
		logrus.SetLevel(logrus.PanicLevel)
	case "fatal":
		logrus.SetLevel(logrus.FatalLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "warn":
		logrus.SetLevel(logrus.WarnLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	default:
		logrus.SetLevel(logrus.WarnLevel)
	}

	switch logFormat {
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{})
	case "text":
		logrus.SetFormatter(&logrus.TextFormatter{
			DisableColors: true,
		})
	default:
		logrus.SetFormatter(&logrus.TextFormatter{})
	}

	logrus.SetOutput(os.Stdout)

	c.logger = logger

	return nil
}

// GetLogger 用于获取全局日志
func (c *LocalConfig) GetLogger() *logrus.Entry {
	return c.logger
}

func (c *LocalConfig) interceptorLogger(l logrus.FieldLogger) logging.Logger {
	return logging.LoggerFunc(func(_ context.Context, lvl logging.Level, msg string, fields ...any) {
		f := make(map[string]any, len(fields)/2)
		i := logging.Fields(fields).Iterator()
		if i.Next() {
			k, v := i.At()
			f[k] = v
		}
		l := l.WithFields(f)

		switch lvl {
		case logging.LevelDebug:
			l.Debug(msg)
		case logging.LevelInfo:
			l.Info(msg)
		case logging.LevelWarn:
			l.Warn(msg)
		case logging.LevelError:
			l.Error(msg)
		default:
			panic(fmt.Sprintf("unknown level %v", lvl))
		}
	})
}
