package sd

import "context"

// Clienter 服务发现接口
type Clienter interface {
	Register(ctx context.Context, name, addr, val string, ttl int64) error
	Deregister() error
}

// Register 注册一个服务
func Register(conn *Connector, name, addr, val string, ttl int64) (Clienter, error) {
	if conn == nil {
		return nil, errConnectorIsNil
	}

	switch conn.Driver {
	case ETCDV3:
		client, err := newEtcdv3Client(Prefix, Namespace, conn)
		if err != nil {
			return client, err
		}

		if err := client.Register(context.TODO(), name, addr, val, ttl); err != nil {
			return client, err
		}

		return client, err
	}

	return nil, errNotSupportDriver
}
