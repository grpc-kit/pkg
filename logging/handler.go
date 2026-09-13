package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

// NewHandler constructs a standard slog handler. The caller owns w and the
// Leveler in options, allowing tests and applications to control both without
// changing process-global logging state.
func NewHandler(w io.Writer, format Format, options *slog.HandlerOptions) slog.Handler {
	if w == nil {
		w = os.Stderr
	}

	configured := cloneHandlerOptions(options)
	configured.ReplaceAttr = chainReplaceAttr(configured.ReplaceAttr)

	if format == FormatJSON {
		return &reservedHandler{handler: slog.NewJSONHandler(w, configured), root: true}
	}
	return &reservedHandler{handler: slog.NewTextHandler(w, configured), root: true}
}

// New constructs a logger backed by NewHandler.
func New(w io.Writer, format Format, options *slog.HandlerOptions) *slog.Logger {
	return slog.New(NewHandler(w, format, options))
}

func cloneHandlerOptions(options *slog.HandlerOptions) *slog.HandlerOptions {
	if options == nil {
		return &slog.HandlerOptions{}
	}
	cloned := *options
	return &cloned
}

func chainReplaceAttr(next func([]string, slog.Attr) slog.Attr) func([]string, slog.Attr) slog.Attr {
	return func(groups []string, attr slog.Attr) slog.Attr {
		if next != nil {
			attr = next(groups, attr)
		}
		if attr.Key == slog.LevelKey {
			if level, ok := attr.Value.Any().(slog.Level); ok {
				attr.Value = slog.StringValue(levelName(level))
			}
		}
		return attr
	}
}

func levelName(level slog.Level) string {
	switch level {
	case LevelFatal:
		return "fatal"
	case LevelPanic:
		return "panic"
	default:
		return strings.ToLower(level.String())
	}
}

type reservedHandler struct {
	handler slog.Handler
	root    bool
}

func (h *reservedHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *reservedHandler) Handle(ctx context.Context, record slog.Record) error {
	clean := slog.NewRecord(record.Time, record.Level, record.Message, record.PC)
	record.Attrs(func(attr slog.Attr) bool {
		clean.AddAttrs(sanitizeAttr(attr, h.root))
		return true
	})
	return h.handler.Handle(ctx, clean)
}

func (h *reservedHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	for index, attr := range attrs {
		attrs[index] = sanitizeAttr(attr, h.root)
	}
	return &reservedHandler{handler: h.handler.WithAttrs(attrs), root: h.root}
}

func (h *reservedHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &reservedHandler{handler: h.handler.WithGroup(name)}
}

func sanitizeAttr(attr slog.Attr, root bool) slog.Attr {
	attr.Value = attr.Value.Resolve()
	if attr.Value.Kind() == slog.KindGroup {
		children := attr.Value.Group()
		childRoot := root && attr.Key == ""
		clean := make([]slog.Attr, 0, len(children))
		for _, child := range children {
			clean = append(clean, sanitizeAttr(child, childRoot))
		}
		attr.Value = slog.GroupValue(clean...)
		return attr
	}
	if root && isReservedKey(attr.Key) {
		attr.Key = "fields." + attr.Key
	}
	return attr
}

func isReservedKey(key string) bool {
	switch key {
	case slog.TimeKey, slog.LevelKey, slog.MessageKey, slog.SourceKey:
		return true
	default:
		return false
	}
}
