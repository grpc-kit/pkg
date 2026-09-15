package sd

import (
	"context"
	"fmt"
	"log/slog"
	"path"
	"strings"
	"sync"
	"time"

	"go.etcd.io/etcd/api/v3/mvccpb"
	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc/resolver"
)

type etcdv3Client struct {
	logger          *slog.Logger
	prefix          string // 注册的前缀
	namespace       string // 所属的命名空间
	serviceName     string // 服务名称
	serviceAddr     string // 服务地址
	client          *clientv3.Client
	lifecycleCtx    context.Context
	lifecycleCancel func()
	mutexState      *sync.RWMutex
	targetState     map[string]resolver.State // 存放目标服务的后端地址
}

// etcdv3Resolver owns the lifecycle of one resolver.Build result. A builder can
// serve multiple gRPC ClientConns, so the ClientConn and watcher must not be
// stored on the shared etcdv3Client.
type etcdv3Resolver struct {
	client   *etcdv3Client
	ctx      context.Context
	cancel   func()
	cc       resolver.ClientConn
	endpoint string
}

func newEtcdv3Client(ctx context.Context, prefix, namespace string, conn *Connector) (*etcdv3Client, error) {
	e := &etcdv3Client{prefix: prefix,
		namespace:   namespace,
		logger:      conn.logger,
		mutexState:  new(sync.RWMutex),
		targetState: make(map[string]resolver.State)}

	conf := clientv3.Config{
		Endpoints:   strings.Split(conn.Hosts, ","),
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

		conf.TLS = tlsConfig
	}

	cli, err := clientv3.New(conf)
	if err != nil {
		return nil, err
	}

	e.client = cli
	lifecycleCtx, lifecycleCancel := context.WithCancel(ctx)
	e.lifecycleCtx = lifecycleCtx
	e.lifecycleCancel = sync.OnceFunc(lifecycleCancel)
	return e, nil
}

// Register 注册服务
func (e *etcdv3Client) Register(ctx context.Context, name, addr, val string, ttl int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	e.serviceName = name
	e.serviceAddr = addr

	go func() {
		for {
			kap, err := e.register(ctx, val, ttl)
			if err == nil {
				err = e.eatKeepAliveMessage(ctx, kap)
			}
			if ctx.Err() != nil {
				return
			}

			logRegistrationRetry(ctx, e.logger, err)

			// TODO; 是否提取为变量
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()

	return nil
}

// Deregister 取消注册
func (e *etcdv3Client) Deregister(ctx context.Context) error {
	defer e.lifecycleCancel()

	_, err := e.client.Delete(ctx, e.regEndpointPath())
	if err != nil {
		return err
	}

	if err := e.release(); err != nil {
		return err
	}

	return nil
}

// Build 实现"resolver.Build"
// 仅当调用"grpc.Dial"时执行，如果在此之间后端服务地址变更，则需要依赖"watch"做自动化更新
func (e *etcdv3Client) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	if target.URL.Scheme != Scheme {
		return nil, errSchemeInvalid
	}

	r, err := e.newResolver(target.Endpoint(), cc)
	if err != nil {
		return nil, err
	}

	// TODO; 从etcd目录获取数据超时时间应该小于2s内
	lookupCtx, cancelLookup := context.WithTimeout(r.ctx, 2*time.Second)
	defer cancelLookup()

	endpointKey := fmt.Sprintf("%v/%v/endpoints", e.basePath(), target.Endpoint())
	resp, err := e.getKey(lookupCtx, endpointKey)
	if err != nil {
		logResolverLookupFailed(lookupCtx, e.logger, err)

		// 如果查询超时，则返回内存中最近一次可用的地址
		err = r.updateState(lookupCtx, resolver.State{})
		if err != nil {
			logResolverStateRestoreFailed(lookupCtx, e.logger, err)
		}

		return r, nil
	}

	adders := make([]resolver.Address, 0)
	for _, v := range resp.Kvs {
		adders = append(adders, resolver.Address{Addr: path.Base(string(v.Key))})
	}
	state := resolver.State{Addresses: adders}

	// 最近一次解析服务地址存入内存以便获取失败时使用
	err = r.updateState(lookupCtx, state)
	if err != nil {
		r.Close()
		logResolverStateUpdateFailed(lookupCtx, e.logger, len(state.Addresses), err)
		return nil, err
	}

	go r.watcher(adders)

	return r, nil
}

func (e *etcdv3Client) newResolver(endpoint string, cc resolver.ClientConn) (*etcdv3Resolver, error) {
	if err := e.lifecycleCtx.Err(); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(e.lifecycleCtx)
	return &etcdv3Resolver{
		client:   e,
		ctx:      ctx,
		cancel:   sync.OnceFunc(cancel),
		cc:       cc,
		endpoint: endpoint,
	}, nil
}

// Scheme 实现"resolver.Scheme"
func (e *etcdv3Client) Scheme() string {
	return Scheme
}

// Close 实现"resolver.Close"，只取消当前 Build 创建的 watcher。
func (r *etcdv3Resolver) Close() {
	r.cancel()
}

// ResolveNow 实现"resolver.Resolver"
func (r *etcdv3Resolver) ResolveNow(o resolver.ResolveNowOptions) {}

func (e *etcdv3Client) basePath() string {
	return fmt.Sprintf("/%v/%v", e.prefix, e.namespace)
}

func (e *etcdv3Client) regEndpointPath() string {
	return fmt.Sprintf("%v/%v/endpoints/%v", e.basePath(), e.serviceName, e.serviceAddr)
}

func (e *etcdv3Client) release() error {
	// etcd连接可能已经释放，这里可能会捕获到错误
	// _ = e.client.Close()
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

	logRegistrationSucceeded(ctx, e.logger, ttl, int64(resp.ID))

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
			logKeepaliveReceived(ctx, e.logger, x.TTL, int64(x.ID))
		case <-ctx.Done():
			// 接收到被取消的信号
			return fmt.Errorf("keepalive receiver cancel")
		case <-time.After(120 * time.Second):
			// TODO; 超过ttl的3倍时间，未接收到keepalive响应体
			return fmt.Errorf("keepavlie response receiver timeout")
		}
	}
}

func (e *etcdv3Client) getKey(ctx context.Context, key string) (*clientv3.GetResponse, error) {
	resp, err := e.client.Get(ctx, key, clientv3.WithPrefix())
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// updateState 更新grpc服务后端地址
func (r *etcdv3Resolver) updateState(ctx context.Context, state resolver.State) error {
	e := r.client
	e.mutexState.Lock()

	memState, foundState := e.targetState[r.endpoint]
	if len(state.Addresses) == 0 && foundState {
		state = memState
	}

	e.targetState[r.endpoint] = state
	e.mutexState.Unlock()

	logResolverStateUpdated(ctx, e.logger, len(state.Addresses))
	return r.cc.UpdateState(state)
}

func (r *etcdv3Resolver) watcher(addrs []resolver.Address) {
	e := r.client
	endpointKey := fmt.Sprintf("%v/%v/endpoints", e.basePath(), r.endpoint)

	for n := range e.client.Watch(r.ctx, endpointKey, clientv3.WithPrefix()) {
		for _, v := range n.Events {
			addr := path.Base(string(v.Kv.Key))

			switch v.Type {
			case mvccpb.PUT:
				// 更新地址
				if !existAddr(addrs, addr) {
					addrs = append(addrs, resolver.Address{Addr: addr})
					err := r.updateState(r.ctx, resolver.State{Addresses: addrs})
					if err != nil {
						return
					}
				}
			case mvccpb.DELETE:
				// 删除地址
				if s, ok := removeAddr(addrs, addr); ok {
					addrs = s
					err := r.updateState(r.ctx, resolver.State{Addresses: addrs})
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
