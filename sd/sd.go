package sd

import (
	"errors"

	"github.com/sirupsen/logrus"
)

const (
	ETCDV3 = iota
)

var (
	Prefix    = "service"
	Namespace = "default"

	errConnectorIsNil   = errors.New("connector is nil")
	errNotSupportDriver = errors.New("not support driver")
	errSchemeInvalid    = errors.New("scheme invalid")
)

type Connector struct {
	logger *logrus.Entry
	Driver int
	Hosts  string
	TLS    *TLSInfo
}

type TLSInfo struct {
	CAFile   string
	CertFile string
	KeyFile  string
}

// Home 用于设置注册服务的前缀
func Home(prefix, namespace string) {
	Prefix = prefix
	Namespace = namespace
}

// NewConnector 用于注册的属性设置
func NewConnector(logger *logrus.Entry, driver int, hosts string) (*Connector, error) {
	return &Connector{
		logger: logger,
		Driver: driver,
		Hosts:  hosts,
	}, nil
}

func (c *Connector) WithTLSInfo(tls *TLSInfo) {
	c.TLS = tls
}
