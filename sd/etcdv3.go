package sd

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"go.etcd.io/etcd/api/v3/mvccpb"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc/resolver"
)

const (
	scheme = "grpc-kit"
)

type etcdv3Client struct {
	logger             *logrus.Entry
	hosts              []string // 主机地址，格式 http://1.1.1.1:2379,http://1.1.12:2379
	prefix             string   // 注册的前缀
	namespace          string   // 所属的命名空间
	serviceName        string   // 服务名称
	serviceAddr        string   // 服务地址
	client             *clientv3.Client
	cc                 resolver.ClientConn
	resolveNowCallback func(resolver.ResolveNowOptions)
	targetState        map[string]resolver.State
}

func newEtcdv3Client(prefix, namespace string, conn *Connector) (*etcdv3Client, error) {
	e := &etcdv3Client{prefix: prefix,
		namespace:   namespace,
		logger:      conn.logger,
		targetState: make(map[string]resolver.State)}
	e.hosts = strings.Split(conn.Hosts, ",")

	etcdv3conf := clientv3.Config{
		Endpoints:   e.hosts,
		DialTimeout: 5 * time.Second,
		// DialOptions: []grpc.DialOption{grpc.WithBlock()},
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
	// return c.client.Close()
	return nil
}

// register 写入数据至etcd
func (c *etcdv3Client) register(ctx context.Context, name, addr, val string, ttl int64) (<-chan *clientv3.LeaseKeepAliveResponse, error) {
	resp, err := c.client.Grant(ctx, ttl)
	if err != nil {
		return nil, err
	}
	_, err = c.client.Put(ctx, c.regEndpointPath(), val, clientv3.WithLease(resp.ID))
	if err != nil {
		return nil, err
	}

	c.logger.Debugf("etcdv3 reg path: %v, ttl: %v, resp id: %v", c.regEndpointPath(), ttl, resp.ID)

	kap, err := c.client.KeepAlive(ctx, resp.ID)
	if err != nil {
		return nil, err
	}

	return kap, nil
}

// eatKeepAliveMessage 检测keepalive是否异常被关闭等，比如：etcd集群异常重连，重新注册服务
func (c *etcdv3Client) eatKeepAliveMessage(ctx context.Context, kap <-chan *clientv3.LeaseKeepAliveResponse) error {
	// lease keepalive response queue is full; dropping response send
	// https://github.com/etcd-io/etcd/blob/master/clientv3/lease.go#L121
	// 需要对keepalive的响应channel做消费，否则会满
	for {
		select {
		case x := <-kap:
			// 按照ttl的时间返回keepalive响应体，如果为nil说明channel被关闭
			if x == nil {
				return fmt.Errorf("keepalive channel is closed")
			}
			c.logger.Debugf("etcd keepalive: %v", x)
		case <-ctx.Done():
			// 接收到被取消的信号
			return fmt.Errorf("keepalive receiver cancel")
		case <-time.After(120 * time.Second):
			// 超过ttl的3倍时间，未接收到keepalive响应体
			return fmt.Errorf("keepavlie response receiver timeout")
		}
	}
}

// Register 注册服务
func (c *etcdv3Client) Register(ctx context.Context, name, addr, val string, ttl int64) error {
	c.serviceName = name
	c.serviceAddr = addr

	go func() {
		for {
			kap, err := c.register(ctx, name, addr, val, ttl)
			if err == nil {
				err = c.eatKeepAliveMessage(ctx, kap)
			}

			c.logger.Errorf("etcd registry found fails, will be retry later, reason: %v", err)

			// TODO; 是否提取为变量
			time.Sleep(5 * time.Second)
		}
	}()

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

// Build 实现 resolver.Build
func (r *etcdv3Client) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	if target.Scheme != scheme {
		return nil, errSchemeInvalid
	}

	var err error
	r.cc = cc

	ctx := context.Background()

	ctxTw, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	endpointsKey := fmt.Sprintf("%v/%v/endpoints", r.basePath(), target.Endpoint)
	resp, err := r.getKey(ctxTw, endpointsKey)
	if err != nil {
		r.logger.Errorf("resolver build getkey err='%v'", err)

		// 如果查询超时，则返回本地最近一次可用的地址
		err = r.cc.UpdateState(r.targetState[target.Endpoint])
		if err != nil {
			r.logger.Errorf("resolver build update state err='%v'", err)
		}
		return r, nil
	}

	addrs := make([]resolver.Address, 0)
	for _, v := range resp.Kvs {
		addrs = append(addrs, resolver.Address{Addr: path.Base(string(v.Key))})
	}
	state := resolver.State{Addresses: addrs}

	// 最近一次该服务地址存入内存以便获取失败时使用
	r.targetState[target.Endpoint] = state

	err = r.cc.UpdateState(state)
	if err != nil {
		return r, err
	}

	// TODO; 存在多次wathc的问题
	// go r.watcher(ctx, endpointsKey, addrs)

	return r, nil
}

// Scheme 实现 resolver.Scheme
func (r *etcdv3Client) Scheme() string {
	return scheme
}

// Close 实现 resolver.Close
// 仅当执行 grpc.ClientConn.Close 时调用
func (r *etcdv3Client) Close() {
	// 没有资源需要释放
}

// ResolveNow 实现 resolver.Resolver
func (r *etcdv3Client) ResolveNow(o resolver.ResolveNowOptions) {
	r.resolveNowCallback(o)
}

func (r *etcdv3Client) watcher(ctx context.Context, endpointsKey string, addrs []resolver.Address) {
	r.logger.Debugf("resolver watcher key = %v", endpointsKey)

	for n := range r.watchKey(ctx, endpointsKey) {
		for _, e := range n.Events {
			addr := path.Base(string(e.Kv.Key))

			// DEBUG
			r.logger.Debugf("resolver watcher found key = %v", string(e.Kv.Key))

			switch e.Type {
			case mvccpb.PUT:
				// 更新地址
				if !existAddr(addrs, addr) {
					addrs = append(addrs, resolver.Address{Addr: addr})
					err := r.cc.UpdateState(resolver.State{Addresses: addrs})
					if err != nil {
						return
					}

					// DEBUG
					fmt.Println("state addrs:", addrs)
				}
			case mvccpb.DELETE:
				// 删除地址
				if s, ok := removeAddr(addrs, addr); ok {
					addrs = s
					err := r.cc.UpdateState(resolver.State{Addresses: addrs})
					if err != nil {
						return
					}

					// DEBUG
					fmt.Println("state addrs:", addrs)
				}
			}
		}
	}
}

func existAddr(addrs []resolver.Address, addr string) bool {
	for idx := range addrs {
		if addrs[idx].Addr == addr {
			return true
		}
	}
	return false
}

func removeAddr(addrs []resolver.Address, addr string) ([]resolver.Address, bool) {
	for idx := range addrs {
		if addrs[idx].Addr == addr {
			// 当前位置由末尾值进行替换，如果存在两个一样的值，则会出现问题
			addrs[idx] = addrs[len(addrs)-1]
			return addrs[:len(addrs)-1], true
		}
	}

	return nil, false
}
