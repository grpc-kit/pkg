// Package logruscompat adapts legacy logrus entries to native slog loggers.
package logruscompat

import (
	"context"
	"log/slog"

	pklogging "github.com/grpc-kit/pkg/logging"
	"github.com/sirupsen/logrus"
)

// NewLogger returns a slog logger that delegates records to entry. A nil or
// malformed entry uses logging.Fallback rather than process-global loggers.
func NewLogger(entry *logrus.Entry) *slog.Logger {
	if entry == nil || entry.Logger == nil {
		return pklogging.Fallback()
	}
	return slog.New(NewHandler(entry))
}

// NewHandler returns an immutable slog handler backed by entry. Callers should
// use NewLogger when entry may be nil.
func NewHandler(entry *logrus.Entry) slog.Handler {
	if entry == nil || entry.Logger == nil {
		return pklogging.Fallback().Handler()
	}
	return &Handler{entry: entry.Dup()}
}

// Handler sends slog records through a legacy logrus Entry.
type Handler struct {
	entry  *logrus.Entry
	groups []string
}

// Enabled reports whether the underlying logrus logger accepts level.
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return h.entry.Logger.IsLevelEnabled(logrusLevel(level))
}

// Handle writes a record while preserving its time, attributes, logger
// formatter/output/hooks, and the most specific available context.
func (h *Handler) Handle(ctx context.Context, record slog.Record) error {
	entry := h.entry
	fields := make(logrus.Fields)
	record.Attrs(func(attr slog.Attr) bool {
		appendAttr(fields, h.groups, attr)
		return true
	})
	if len(fields) != 0 {
		entry = entry.WithFields(fields)
	}
	if !record.Time.IsZero() {
		entry = entry.WithTime(record.Time)
	}
	if ctx != nil && ctx != context.Background() {
		entry = entry.WithContext(ctx)
	}

	writeEntry(entry, logrusLevel(record.Level), record.Message)
	return nil
}

// WithAttrs returns a derived handler without changing its parent.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	fields := fieldsFromAttrs(h.groups, attrs)
	entry := h.entry
	if len(fields) != 0 {
		entry = entry.WithFields(fields)
	}
	return &Handler{entry: entry, groups: append([]string(nil), h.groups...)}
}

// WithGroup returns a derived handler that prefixes subsequent attributes.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &Handler{entry: h.entry, groups: appendGroup(h.groups, name)}
}

func writeEntry(entry *logrus.Entry, level logrus.Level, message string) {
	if level != logrus.PanicLevel {
		entry.Log(level, message)
		return
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			panicEntry, ok := recovered.(*logrus.Entry)
			if !ok || panicEntry.Level != logrus.PanicLevel {
				panic(recovered)
			}
		}
	}()
	entry.Log(level, message)
}
