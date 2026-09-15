package logging

import (
	"log/slog"
	"os"
	"sync"
)

var fallback = sync.OnceValue(func() *slog.Logger {
	return New(os.Stderr, FormatText, &slog.HandlerOptions{Level: slog.LevelInfo})
})

// Fallback returns the explicit logger used when a caller supplies nil. It is
// independent from slog.Default and writes Info-and-above text logs to stderr.
func Fallback() *slog.Logger {
	return fallback()
}

// OrFallback normalizes a possibly nil logger.
func OrFallback(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return Fallback()
	}
	return logger
}
