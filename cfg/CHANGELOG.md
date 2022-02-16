# Changelog

名称 | 说明
------------|----------
Added       | 添加新功能
Changed     | 功能的变更
Deprecated  | 未来会删除
Removed     | 之前为Deprecated状态，此版本被移除
Fixed       | 功能的修复
Security    | 有关安全问题的修复

## [Unreleased]

### Added

- grpc_address支持未监听127.0.0.1地址

## [0.1.3] - 2021-06-02

### Added

- 更改配置toml为yaml格式
- 添加http basic与oidc认证支持

## [0.1.2] - 2021-01-07

### Changed

- 根配置结构更改为引用形式，防止默认类型的零值，困扰判断类型存在
- 服务注册内容不在提供用户自定义，强制写入本地配置内容至注册中心
- 用户可自定义gRPC的一元拦截器，并以自定义为高优先级可覆盖默认值
- 简化模版注册流程，对gateway的handler也通过cfg.Register方法实现

### Added

- 通用gRPC部分方法的实现
- 实现服务注册与撤销方法
- 服务注册配置新增Heartbeat时间，代表ttl
- 客户端与服务端默认流拦截器的支持
- 支持GRPC_KIT_PUHLIC_IP变量实现IP地址注册
- 可支持配置pprof的开关闭

## [0.1.0] - 2020-02-14

### Added

- 首次发布
