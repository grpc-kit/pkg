package sd

import (
	"context"
	"fmt"
	"path"

	"go.etcd.io/etcd/api/v3/mvccpb"
	"google.golang.org/grpc/resolver"
)

const (
	scheme = "grpc-kit"
)

type etcdv3Resolver struct {
	conn               *Connector
	client             *etcdv3Client
	cc                 resolver.ClientConn
	resolveNowCallback func(resolver.ResolveNowOptions)
}

// NewResolver xx
func NewResolver(conn *Connector) resolver.Builder {
	return &etcdv3Resolver{conn: conn}
}

// Build xx
func (r *etcdv3Resolver) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	if target.Scheme != scheme {
		return nil, errSchemeInvalid
	}

	var err error
	if r.client == nil {
		r.client, err = newEtcdv3Client(Prefix, Namespace, r.conn)
		if err != nil {
			return nil, err
		}
	}

	r.cc = cc

	resolver.Register(r)

	ctx := context.Background()
	endpointsKey := fmt.Sprintf("%v/%v/endpoints", r.client.basePath(), target.Endpoint)
	resp, err := r.client.getKey(ctx, endpointsKey)
	if err != nil {
		return nil, err
	}

	addrs := make([]resolver.Address, 0)
	for _, v := range resp.Kvs {
		addrs = append(addrs, resolver.Address{Addr: path.Base(string(v.Key))})
	}
	r.cc.UpdateState(resolver.State{Addresses: addrs})

	go r.watcher(ctx, endpointsKey, addrs)

	return r, nil
}

// Scheme xx
func (r *etcdv3Resolver) Scheme() string {
	return scheme
}

// Close 实现 resolver.Close
func (r *etcdv3Resolver) Close() {
	if err := r.client.release(); err != nil {
		r.conn.logger.Errorf("close etcd err: %v", err)
	}
}

// ResolveNow 实现 resolver.Resolver
func (r *etcdv3Resolver) ResolveNow(o resolver.ResolveNowOptions) {
	r.resolveNowCallback(o)
}

func (r *etcdv3Resolver) watcher(ctx context.Context, endpointsKey string, addrs []resolver.Address) {
	for n := range r.client.watchKey(ctx, endpointsKey) {
		for _, e := range n.Events {
			addr := path.Base(string(e.Kv.Key))

			switch e.Type {
			case mvccpb.Event_EventType(mvccpb.PUT):
				// 更新地址
				if !existAddr(addrs, addr) {
					addrs = append(addrs, resolver.Address{Addr: addr})
					// r.cc.NewAddress(addrs)
					r.cc.UpdateState(resolver.State{Addresses: addrs})
				}
			case mvccpb.Event_EventType(mvccpb.DELETE):
				// 删除地址
				if s, ok := removeAddr(addrs, addr); ok {
					addrs = s
					// r.cc.NewAddress(addrs)
					r.cc.UpdateState(resolver.State{Addresses: addrs})
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
