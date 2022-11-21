package cfg

import (
	"os"

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
