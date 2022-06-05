package sd

import (
	"context"
	"fmt"
	"path"
	"strings"
	"sync"
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
	mutexState         *sync.RWMutex
	mutexWatch         *sync.RWMutex
	targetState        map[string]resolver.State
	targetWatch        map[string]bool
}

func newEtcdv3Client(prefix, namespace string, conn *Connector) (*etcdv3Client, error) {
	e := &etcdv3Client{prefix: prefix,
		namespace:   namespace,
		logger:      conn.logger,
		mutexState:  new(sync.RWMutex),
		mutexWatch:  new(sync.RWMutex),
		targetState: make(map[string]resolver.State),
		targetWatch: make(map[string]bool)}
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

func (e *etcdv3Client) basePath() string {
	return fmt.Sprintf("/%v/%v", e.prefix, e.namespace)
}

func (e *etcdv3Client) regEndpointPath() string {
	return fmt.Sprintf("%v/%v/endpoints/%v", e.basePath(), e.serviceName, e.serviceAddr)
}

func (e *etcdv3Client) release() error {
	return nil
}

// register 写入数据至etcd
func (e *etcdv3Client) register(ctx context.Context, val string, ttl int64) (<-chan *clientv3.LeaseKeepAliveResponse, error) {
	resp, err := e.client.Grant(ctx, ttl)
	if err != nil {
		return nil, err
	}
	_, err = e.client.Put(ctx, e.regEndpointPath(), val, clientv3.WithLease(resp.ID))
	if err != nil {
		return nil, err
	}

	e.logger.Debugf("etcdv3 reg path: %v, ttl: %v, resp id: %v", e.regEndpointPath(), ttl, resp.ID)

	kap, err := e.client.KeepAlive(ctx, resp.ID)
	if err != nil {
		return nil, err
	}

	return kap, nil
}

// eatKeepAliveMessage 检测keepalive是否异常被关闭等，比如：etcd集群异常重连，重新注册服务
func (e *etcdv3Client) eatKeepAliveMessage(ctx context.Context, kap <-chan *clientv3.LeaseKeepAliveResponse) error {
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
			e.logger.Debugf("etcd keepalive: %v", x)
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
func (e *etcdv3Client) Register(ctx context.Context, name, addr, val string, ttl int64) error {
	e.serviceName = name
	e.serviceAddr = addr

	go func() {
		for {
			kap, err := e.register(ctx, val, ttl)
			if err == nil {
				err = e.eatKeepAliveMessage(ctx, kap)
			}

			e.logger.Errorf("etcd registry found fails, will be retry later, reason: %v", err)

			// TODO; 是否提取为变量
			time.Sleep(5 * time.Second)
		}
	}()

	return nil
}

// Deregister 取消注册
func (e *etcdv3Client) Deregister() error {
	_, err := e.client.Delete(context.Background(), e.regEndpointPath())
	if err != nil {
		return err
	}

	if err := e.release(); err != nil {
		return err
	}

	return nil
}

func (e *etcdv3Client) getKey(ctx context.Context, key string) (*clientv3.GetResponse, error) {
	resp, err := e.client.Get(ctx, key, clientv3.WithPrefix())
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// updateState 更新grpc服务后端地址
func (e *etcdv3Client) updateState(endpoint string, state resolver.State) error {
	e.mutexState.Lock()
	defer e.mutexState.Unlock()

	memState, foundState := e.targetState[endpoint]
	if len(state.Addresses) == 0 && foundState {
		state = memState
	}

	e.logger.Debugf("etcdv3 registry update endpoint: %v, state addrs: %v", endpoint, state.Addresses)

	e.targetState[endpoint] = state
	return e.cc.UpdateState(state)
}

// Build 实现"resolver.Build"
// 仅当调用"grpc.Dial"时执行，如果在此之间后端服务地址变更，则需要依赖"watch"做自动化更新
func (e *etcdv3Client) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	if target.Scheme != scheme {
		return nil, errSchemeInvalid
	}

	e.cc = cc

	// TODO; 从etcd目录获取数据超时时间应该小于2s内
	ctx, cancel := context.WithTimeout(context.TODO(), 2*time.Second)
	defer cancel()

	endpointKey := fmt.Sprintf("%v/%v/endpoints", e.basePath(), target.Endpoint)
	resp, err := e.getKey(ctx, endpointKey)
	if err != nil {
		e.logger.Errorf("resolver build getkey err: %v, will use last resolver address", err)

		// 如果查询超时，则返回内存中最近一次可用的地址
		err = e.updateState(target.Endpoint, resolver.State{})
		if err != nil {
			e.logger.Errorf("resolver build update state err: %v", err)
		}

		return e, nil
	}

	adders := make([]resolver.Address, 0)
	for _, v := range resp.Kvs {
		adders = append(adders, resolver.Address{Addr: path.Base(string(v.Key))})
	}
	state := resolver.State{Addresses: adders}

	// 最近一次解析服务地址存入内存以便获取失败时使用
	err = e.updateState(target.Endpoint, state)
	if err != nil {
		e.logger.Errorf("resolver build update state err: %v", err)
		return nil, err
	}

	e.mutexWatch.Lock()
	defer e.mutexWatch.Unlock()
	if !e.targetWatch[target.Endpoint] {
		go e.watcher(target.Endpoint, adders)
		e.targetWatch[target.Endpoint] = true
	}

	return e, nil
}

// Scheme 实现 resolver.Scheme
func (e *etcdv3Client) Scheme() string {
	return scheme
}

// Close 实现 resolver.Close
// 仅当执行 grpc.ClientConn.Close 时调用
func (e *etcdv3Client) Close() {
	// 没有资源需要释放
}

// ResolveNow 实现 resolver.Resolver
func (e *etcdv3Client) ResolveNow(o resolver.ResolveNowOptions) {
	e.logger.Infof("ResolveNow...")

	e.resolveNowCallback(o)
}

func (e *etcdv3Client) watcher(endpoint string, addrs []resolver.Address) {
	endpointKey := fmt.Sprintf("%v/%v/endpoints", e.basePath(), endpoint)

	// 这里context不能被取消或超时
	ctx := context.Background()
	for n := range e.client.Watch(ctx, endpointKey, clientv3.WithPrefix()) {
		for _, v := range n.Events {
			addr := path.Base(string(v.Kv.Key))

			switch v.Type {
			case mvccpb.PUT:
				// 更新地址
				if !existAddr(addrs, addr) {
					addrs = append(addrs, resolver.Address{Addr: addr})
					err := e.updateState(endpoint, resolver.State{Addresses: addrs})
					if err != nil {
						return
					}
				}
			case mvccpb.DELETE:
				// 删除地址
				if s, ok := removeAddr(addrs, addr); ok {
					addrs = s
					err := e.updateState(endpoint, resolver.State{Addresses: addrs})
					if err != nil {
						return
					}
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
