package logruscompat

import (
	"log/slog"
	"strings"

	"github.com/sirupsen/logrus"
)

func fieldsFromAttrs(groups []string, attrs []slog.Attr) logrus.Fields {
	fields := make(logrus.Fields)
	for _, attr := range attrs {
		appendAttr(fields, groups, attr)
	}
	return fields
}

func appendAttr(fields logrus.Fields, groups []string, attr slog.Attr) {
	attr.Value = attr.Value.Resolve()
	if attr.Equal(slog.Attr{}) {
		return
	}

	if attr.Value.Kind() == slog.KindGroup {
		nextGroups := groups
		if attr.Key != "" {
			nextGroups = appendGroup(groups, attr.Key)
		}
		for _, child := range attr.Value.Group() {
			appendAttr(fields, nextGroups, child)
		}
		return
	}

	keyParts := groups
	if attr.Key != "" {
		keyParts = appendGroup(groups, attr.Key)
	}
	if len(keyParts) == 0 {
		return
	}
	fields[strings.Join(keyParts, ".")] = attr.Value.Any()
}

func appendGroup(groups []string, group string) []string {
	result := make([]string, len(groups), len(groups)+1)
	copy(result, groups)
	return append(result, group)
}
