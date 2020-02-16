# 1 - 注册与发现

服务注册发现均由etcd实现，需通过证书访问。

```
https://node1.example.com:2379
https://node2.example.com:2379
https://node3.example.com:2379
```

## 1.1 - 注册路径

```
/${root_path}/${namespace}/${service_name}/${endpoint_name}/${service_addr}
```

参数 | 说明  | 示例
-----|-------|-------------
root_path     | 注册的根地址         | 默认为：services
namespace     | 命名空间             | 默认为：default
endpoint_name | 微服务提供地址的父级 | 统一固定为：endpoints
endpoint_addr | 具体一个微服务的地址 | 比如：lb.example.com:10080

示例：

```
/services/default/opensearch.v1.monitors.api.example.com/endpoints/c1.k8s.example.com:60060
/services/default/opensearch.v1.monitors.api.example.com/endpoints/c2.k8s.example.com:60060
/services/default/opensearch.v1.monitors.api.example.com/endpoints/c3.k8s.example.com:60060
```

# 2 - 使用示例

```
serviceName := "opensearch.v1.monitors"
publicAddress := "lb.example.com:10080"

sd.Home("service", "namespace")

logger := logrus.WithFields(logrus.Fields{"service_name": serviceName})

connector, err := sd.NewConnector(logger, sd.ETCDV3, "http://127.0.0.1:2379")
if err != nil {
}

// set tls
/*
tls := &sd.TLSInfo{
    CAFile:   lc.Discoverer.TLS.CAFile,
    CertFile: lc.Discoverer.TLS.CertFile,
    KeyFile:  lc.Discoverer.TLS.KeyFile,
}
connector.WithTLSInfo(tls)
*/

reg, err := sd.Register(connector, serviceName, publicAddress, "register value", 30)
if err != nil {
}

defer func() {
    if err := reg.Deregister(); err != nil {
        return
    }
}()
```
