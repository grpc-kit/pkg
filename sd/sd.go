package sd

import (
	"context"
	"errors"
	"log/slog"

	"github.com/grpc-kit/pkg/logging"
	"google.golang.org/grpc/resolver"
)

const (
	// ETCDV3 xx
	ETCDV3 = iota
)

var (
	// Prefix xx
	Prefix = "service"
	// Namespace xx
	Namespace = "default"
	// Scheme xx
	Scheme = "grpc-kit"
)

var (
	errConnectorIsNil   = errors.New("connector is nil")
	errNotSupportDriver = errors.New("not support driver")
	errSchemeInvalid    = errors.New("scheme invalid")
)

// Registry 服务注册发现，TODO：（之后会进行改造，主要支持kubernetes）
type Registry interface {
	// Register 注册服务信息至etcd等
	Register(ctx context.Context, name, addr, val string, ttl int64) error
	// Deregister 使用调用方上下文删除服务信息至etcd等
	Deregister(ctx context.Context) error
	// Build 实现 resolver.Builder
	Build(resolver.Target, resolver.ClientConn, resolver.BuildOptions) (resolver.Resolver, error)
	// Scheme 实现 resolver.Builder
	Scheme() string
}

// Connector 连接器
type Connector struct {
	logger *slog.Logger
	Driver int
	Hosts  string
	TLS    *TLSInfo
}

// TLSInfo 证书结构
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

// Register 使用调用方上下文注册一个服务。
func Register(ctx context.Context, conn *Connector, name, addr, val string, ttl int64) (Registry, error) {
	if conn == nil {
		return nil, errConnectorIsNil
	}

	switch conn.Driver {
	case ETCDV3:
		client, err := newEtcdv3Client(Prefix, Namespace, conn)
		if err != nil {
			return client, err
		}

		if err := client.Register(ctx, name, addr, val, ttl); err != nil {
			return client, err
		}

		return client, err
	}

	return nil, errNotSupportDriver
}

// NewConnector 用于注册的属性设置
func NewConnector(logger *slog.Logger, driver int, hosts string) (*Connector, error) {
	return &Connector{
		logger: logging.OrFallback(logger),
		Driver: driver,
		Hosts:  hosts,
	}, nil
}

// WithTLSInfo 设置认证
func (c *Connector) WithTLSInfo(tls *TLSInfo) {
	c.TLS = tls
}
