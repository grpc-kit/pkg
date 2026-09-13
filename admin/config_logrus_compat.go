package admin

import (
	"github.com/grpc-kit/pkg/logging/logruscompat"
	"github.com/sirupsen/logrus"
)

// WithLogger serves legacy callers that supply a logrus entry.
//
// Deprecated: use WithSlogLogger. This compatibility function will be removed
// when the v0.5.0 slog API cutover restores the WithLogger name.
func WithLogger(logger *logrus.Entry) Options {
	return WithSlogLogger(logruscompat.NewLogger(logger))
}
