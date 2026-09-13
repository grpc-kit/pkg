package audit

import (
	"github.com/grpc-kit/pkg/logging/logruscompat"
	"github.com/sirupsen/logrus"
)

// WithLogger serves legacy callers that supply a logrus entry.
//
// Deprecated: use WithSlogLogger.
func WithLogger(logger *logrus.Entry) Option {
	return WithSlogLogger(logruscompat.NewLogger(logger))
}
