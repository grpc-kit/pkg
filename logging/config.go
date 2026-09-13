// Package logging provides the native slog infrastructure used by pkg.
package logging

import (
	"log/slog"
	"strings"
)

// Format selects the output format used by NewHandler.
type Format string

const (
	FormatText Format = "text"
	FormatJSON Format = "json"

	// LevelFatal and LevelPanic preserve the legacy severity names without
	// adding process exit or panic behavior to slog.
	LevelFatal = slog.LevelError + 4
	LevelPanic = slog.LevelError + 8
)

// ParseLevel parses the levels supported by the legacy debugger config.
// The boolean reports whether value was recognized.
func ParseLevel(value string) (slog.Level, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn", "warning":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	case "fatal":
		return LevelFatal, true
	case "panic":
		return LevelPanic, true
	default:
		return 0, false
	}
}

// ParseFormat parses a supported output format. The boolean reports whether
// value was recognized.
func ParseFormat(value string) (Format, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case string(FormatText):
		return FormatText, true
	case string(FormatJSON):
		return FormatJSON, true
	default:
		return "", false
	}
}
