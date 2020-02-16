package sd

import (
	"context"
	"fmt"
	"path"

	// etcdv3.3.x版本的clientv3还是引用coreos/etcd下类型
	// "go.etcd.io/etcd/mvcc/mvccpb"
	mvccpb "github.com/coreos/etcd/mvcc/mvccpb"
	"google.golang.org/grpc/resolver"
)

const (
	scheme = "grpc-kit"
)

type etcdv3Resolver struct {
	conn   *Connector
	client *etcdv3Client
	cc     resolver.ClientConn
}

// NewResolver xx
func NewResolver(conn *Connector) resolver.Builder {
	return &etcdv3Resolver{conn: conn}
}

func (r *etcdv3Resolver) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOption) (resolver.Resolver, error) {
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

	endpointsKey := fmt.Sprintf("%v/%v/endpoints", r.client.basePath(), target.Endpoint)
	go r.watcher(context.Background(), endpointsKey)

	return r, nil
}

func (r *etcdv3Resolver) Scheme() string {
	return scheme
}

func (r *etcdv3Resolver) Close() {
	if err := r.client.release(); err != nil {
		fmt.Println("close etcd err:", err)
	}
}

func (r *etcdv3Resolver) ResolveNow(t resolver.ResolveNowOption) {
}

func (r *etcdv3Resolver) watcher(ctx context.Context, endpointsKey string) {
	resp, err := r.client.getKey(ctx, endpointsKey)
	if err != nil {
		return
	}

	addrs := make([]resolver.Address, 0)
	for _, v := range resp.Kvs {
		addrs = append(addrs, resolver.Address{Addr: path.Base(string(v.Key)), Type: resolver.GRPCLB})
	}

	r.cc.NewAddress(addrs)

	for n := range r.client.watchKey(ctx, endpointsKey) {
		for _, e := range n.Events {
			addr := path.Base(string(e.Kv.Key))

			switch e.Type {
			case mvccpb.Event_EventType(mvccpb.PUT):
				// 更新地址
				if !existAddr(addrs, addr) {
					addrs = append(addrs, resolver.Address{Addr: addr, Type: resolver.GRPCLB})
					r.cc.NewAddress(addrs)
				}
			case mvccpb.Event_EventType(mvccpb.DELETE):
				// 删除地址
				if s, ok := removeAddr(addrs, addr); ok {
					addrs = s
					r.cc.NewAddress(addrs)
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
