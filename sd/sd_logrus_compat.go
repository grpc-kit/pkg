package sd

import (
	"github.com/grpc-kit/pkg/logging/logruscompat"
	"github.com/sirupsen/logrus"
)

// NewConnector returns a Connector backed by a legacy logrus entry.
//
// Deprecated: use NewConnectorWithSlog.
func NewConnector(logger *logrus.Entry, driver int, hosts string) (*Connector, error) {
	return NewConnectorWithSlog(logruscompat.NewLogger(logger), driver, hosts)
}
