package auth

import (
	"github.com/grpc-kit/pkg/logging/logruscompat"
	"github.com/sirupsen/logrus"
)

// WithLoggerOption serves legacy callers that supply a logrus entry.
//
// Deprecated: use WithSlogLoggerOption. This compatibility method will be
// removed when the v0.5.0 slog API cutover restores the WithLoggerOption name.
func (c *Client) WithLoggerOption(logger *logrus.Entry) *Client {
	return c.WithSlogLoggerOption(logruscompat.NewLogger(logger))
}
