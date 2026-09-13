package errs

import (
	"github.com/grpc-kit/pkg/logging/logruscompat"
	"github.com/sirupsen/logrus"
)

// WithLogger serves legacy callers that supply a logrus entry.
//
// Deprecated: use WithSlogLogger.
func (s *Status) WithLogger(logger *logrus.Entry, format string, err error) *Status {
	return s.WithSlogLogger(logruscompat.NewLogger(logger), format, err)
}
