package sd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/pkg/transport"
	"github.com/sirupsen/logrus"
)

type etcdv3Client struct {
	logger      *logrus.Entry
	hosts       []string // 主机地址，格式 http://1.1.1.1:2379,http://1.1.12:2379
	prefix      string   // 注册的前缀
	namespace   string   // 所属的命名空间
	serviceName string   // 服务名称
	serviceAddr string   // 服务地址
	client      *clientv3.Client
}

func newEtcdv3Client(prefix, namespace string, conn *Connector) (*etcdv3Client, error) {
	e := &etcdv3Client{prefix: prefix, namespace: namespace, logger: conn.logger}
	e.hosts = strings.Split(conn.Hosts, ",")

	etcdv3conf := clientv3.Config{
		Endpoints:   e.hosts,
		DialTimeout: 5 * time.Second,
	}

	if conn.TLS != nil {
		tlsInfo := transport.TLSInfo{
			TrustedCAFile: conn.TLS.CAFile,
			CertFile:      conn.TLS.CertFile,
			KeyFile:       conn.TLS.KeyFile,
		}

		tlsConfig, err := tlsInfo.ClientConfig()
		if err != nil {
			return nil, err
		}

		etcdv3conf.TLS = tlsConfig
	}

	cli, err := clientv3.New(etcdv3conf)
	if err != nil {
		return nil, err
	}

	e.client = cli
	return e, nil
}

func (c *etcdv3Client) basePath() string {
	return fmt.Sprintf("/%v/%v", c.prefix, c.namespace)
}

func (c *etcdv3Client) regEndpointPath() string {
	return fmt.Sprintf("%v/%v/endpoints/%v", c.basePath(), c.serviceName, c.serviceAddr)
}

func (c *etcdv3Client) release() error {
	return c.client.Close()
}

// Register 注册服务
func (c *etcdv3Client) Register(ctx context.Context, name, addr, val string, ttl int64) error {
	resp, err := c.client.Grant(ctx, ttl)
	if err != nil {
		return err
	}

	c.serviceName = name
	c.serviceAddr = addr

	_, err = c.client.Put(ctx, c.regEndpointPath(), val, clientv3.WithLease(resp.ID))
	if err != nil {
		return err
	}

	c.logger.Debugf("etcdv3 reg path: %v, ttl: %v, resp id: %v", c.regEndpointPath(), ttl, resp.ID)

	sp, err := c.client.KeepAlive(ctx, resp.ID)
	if err != nil {
		return err
	}

	// lease keepalive response queue is full; dropping response send
	// https://github.com/etcd-io/etcd/blob/master/clientv3/lease.go#L121
	go func(sp <-chan *clientv3.LeaseKeepAliveResponse) {
		for range sp {
		}
	}(sp)

	return nil
}

// Deregister 取消注册
func (c *etcdv3Client) Deregister() error {
	_, err := c.client.Delete(context.Background(), c.regEndpointPath())
	if err != nil {
		return err
	}

	if err := c.release(); err != nil {
		return err
	}

	return nil
}

func (c *etcdv3Client) getKey(ctx context.Context, key string) (*clientv3.GetResponse, error) {
	resp, err := c.client.Get(ctx, key, clientv3.WithPrefix())
	if err != nil {
		return resp, err
	}

	return resp, nil
}

func (c *etcdv3Client) watchKey(ctx context.Context, key string) clientv3.WatchChan {
	return c.client.Watch(ctx, key, clientv3.WithPrefix())
}
