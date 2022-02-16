# 概述

提供grpc-kit微服务脚手架的通用配置规范

## 术语约定

### 连接地址

参数 | 类型 | 说明 | 示例
-----|------|---------|----
host | string | 主机IPv4或IPv6地址 | 127.0.0.1
port | int | 主机端口号 | 6379
address | string | 不包含协议，由主机IP与端口组成 | 127.0.0.1:6379 或 [fe80::1%lo0]:53
endpoints | []string | 由协议、IP、端口组成，多个通过逗号","分割 | https://node1:2379,https://node2:2379,https://node3:2379

### 其他类型

参数 | 类型 | 说明 | 示例
-----|------|---------|----
driver | string | 配置支持的驱动 | etcdv3、redis等
enable | bool | 是否开启这个功能 | true、false

## 配置示例

```yaml
# https://github.com/grpc-kit/cfg/blob/master/app-sample.yaml

# 基础服务配置
services:
  # 服务注册的前缀，全局统一
  root_path: service
  # 服务注册的空间，全局统一
  namespace: example
  # 服务的代码，设置后不可变更
  service_code: cmdb.v1.commons
  # 接口网关的地址
  api_endpoint: api.grpc-kit.com
  # 服务所监听的grpc地址（如未设置，自动监听在127.0.0.1的随机端口）
  grpc_address: 127.0.0.1:10081
  # 服务所监听的http地址（如未设置，则不开启gateway服务）
  http_address: 127.0.0.1:10080
  # 服务注册，外部网络可连接的grpc地址（一般等同于grpc-address）
  public_address: ""

# 服务注册配置
discover:
  driver: etcdv3
  heartbeat: 15
  endpoints:
    - http://127.0.0.1:2379
  #discover:
  #  tls:
  #    ca_file: /opt/certs/etcd-ca.pem
  #    cert_file: /opt/certs/etcd.pem
  #    key_file: /opt/certs/etcd-key.pem

# 认证鉴权配置
security:
  enable: true
  # 认证：谁在登录
  authentication:
    # 跳过认证的rpc方法
    insecure_rpcs:
      - SearchHosts
    oidc_provider:
      issuer: https://accounts.example.com
      config:
        # 必须验证token.aud是否与client_id相等
        client_id: example
        # 允许的签名算法类别
        supported_signing_algs:
          - RS256
        # 忽略token.aud与client_id的验证
        skip_client_id_check: true
        # 忽略token是否过期的验证
        skip_expiry_check: false
        # 忽略token issuer的验证
        skip_issuer_check: true
    http_users:
      - username: user1
        password: pass1
  # TODO; 鉴权：能做什么
  authorization:

# 关系数据配置
database:
  driver: postgres
  dbname: demo
  user: demo
  password: grpc-kit
  host: 127.0.0.1
  port: 5432
  sslmode: disable
  connect_timeout: 10

# 缓存服务配置
cachebuf:
  enable: true
  driver: redis
  address: 127.0.0.1:6379
  password: ""

# 日志调试配置
debugger:
  enable_pprof: true
  log_level: debug
  log_format: text

# 链路追踪配置
opentracing:
  enable: true
  host: 127.0.0.1
  port: 6831
  
# 事件通道配置
cloudevents:
  protocol: "kafka_sarama"
  kafka_sarama:
    topic: "uptime-test"
    brokers:
      - 127.0.0.1:19092
      - 127.0.0.1:29092
      - 127.0.0.1:39092
    config:
      net:
        tls:
          enable: false
        sasl:
          enable: true
          mechanism: "SCRAM-SHA-256"
          user: "uptime"
          password: "testkey"
      producer:
        required_acks: 1
        return:
          successes: false
          errors: true
      consumer:
        group:
          rebalance:
            strategy: range
        offsets:
          auto_commit:
            enable: true
            interval: 1s
      version: "2.4.0"

# 应用私有配置
independent:
  name: grpc-kit
```

### 注册地址说明

在services中所配置的public-address地址是grpc服务，与其他服务之间必须能正常通讯。如果在k8s环境下可考虑设置环境变量GRPC_KIT_PUHLIC_IP把POD IP传递，如：

```yaml
...
spec:
  template:
    spec:
      containers:
      - args:
        - /opt/service
        - --config
        - /opt/config/app.toml
        env:
        - name: GRPC_KIT_PUHLIC_IP
          valueFrom:
            fieldRef:
              apiVersion: v1
              fieldPath: status.podIP
...
```
