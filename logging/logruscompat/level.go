package logruscompat

import (
	"log/slog"

	pklogging "github.com/grpc-kit/pkg/logging"
	"github.com/sirupsen/logrus"
)

func logrusLevel(level slog.Level) logrus.Level {
	switch {
	case level < slog.LevelInfo:
		return logrus.DebugLevel
	case level < slog.LevelWarn:
		return logrus.InfoLevel
	case level < slog.LevelError:
		return logrus.WarnLevel
	case level < pklogging.LevelFatal:
		return logrus.ErrorLevel
	case level < pklogging.LevelPanic:
		return logrus.FatalLevel
	default:
		return logrus.PanicLevel
	}
}
