# `pkg` 开发规范

本文件适用于 `pkg/` 目录及其子目录。`pkg` 是独立的 Go module，模块路径为
`github.com/grpc-kit/pkg`；除非另有更近的 `AGENTS.md`，本文件中的规则对所有
子包生效。

## 项目结构

- `pkg/rpc`、`pkg/errs`、`pkg/crypto`、`pkg/extension`、`pkg/file`、`pkg/sd`、
  `pkg/signal`、`pkg/vars` 提供底层或通用能力。
- `pkg/auth` 提供认证相关能力；`pkg/cfg` 负责配置和运行时组合；`pkg/admin`
  提供管理业务；`pkg/lion` 提供 Ent 数据访问层；`pkg/api` 保存生成的协议代码。
- 修改前先确认目标包的职责和依赖方向；不要为了复用少量逻辑引入更高层包。

## 常用命令

以下命令均在 `pkg/` 目录执行：

```sh
go test ./...                 # 全量测试
go test ./rpc/... ./cfg/...   # 只验证受影响的基础/配置包（按实际改动调整）
go vet ./...                  # 提交前的静态检查
gofmt -w path/to/changed.go   # 格式化修改过的 Go 文件
go generate ./lion/           # 仅在修改 Ent schema/生成逻辑后执行
```

不要手工修改带有 `Code generated ... DO NOT EDIT.` 标记的文件；应修改其源文件
后重新生成，并检查生成结果是否包含在变更中。若测试因数据库、外部服务或其他
环境依赖失败，必须在交付说明中记录失败命令和原因，不得表述为测试通过。

## 依赖方向

- `pkg/cfg` 是配置与运行时组合层，可以按需引入其他 `pkg/...` 包。
- `pkg/rpc` 是底层基础包，禁止直接引入 `pkg/auth`、`pkg/cfg`、`pkg/admin`、`pkg/lion` 等业务或上层包，避免形成循环依赖。
- `pkg/rpc` 只应依赖标准库和底层通用依赖。新增 import 前必须检查依赖方向，不能通过业务类型反向污染基础包。
- 需要使用具体业务类型的类型安全 API，应放在 `pkg/cfg` 或更上层；`pkg/rpc` 只提供无业务依赖的通用能力。
- `pkg/errs`、`pkg/crypto` 等通用包也不得反向依赖 `pkg/admin`、`pkg/cfg` 或其他业务包。
- 测试代码也应遵守依赖方向；不要仅为测试方便在底层包中引入上层实现。

## Context 认证数据

- `pkg/rpc` 使用自定义、未导出的 context key，禁止使用字符串作为 key。
- `tokenClaimsKey` 只保存已经完成认证校验的 Claims，不保存原始 Bearer Token、密码、签名密钥或私钥。
- `pkg/rpc` 使用通用 API `ContextWithTokenClaims` 和 `GetTokenClaimsFromContext`，不得在其中引入具体认证 Claims 类型。
- `auth.AccessTokenClaims` 等具体类型必须在 `pkg/cfg`、`pkg/admin` 等上层包中完成类型断言和业务处理。
- `ContextWithIDToken` 和 `GetIDTokenFromContext` 仅用于历史兼容，新的调用代码应使用通用 Token Claims API。
- 如果认证数据模型发生变化，应优先新增兼容 API，避免直接改变旧方法的行为。

## 安全注意事项

- 不要在源码、测试固件、示例配置、日志或错误信息中提交真实 Token、密码、私钥、
  数据库凭据或生产端点；使用明显的测试值或环境变量。
- 处理认证、授权、OAuth、MFA、密钥轮换或加密逻辑时，必须补充/更新失败路径和
  边界条件测试，并检查是否会泄露敏感信息。
- 解析外部输入时保留现有校验、超时和权限检查；不要为了兼容调用方而放宽安全约束。

## 修改与验证

- 修改跨包 API 时，同时检查所有调用方和现有兼容测试。
- 修改公共 API、认证上下文、错误映射或生成源文件时，优先补充回归测试，并检查
  `go vet` 和受影响包的测试结果。
- Go 文件提交前运行 `gofmt`；至少执行受影响包的 `go test`，条件允许时执行 `go test ./...`。
- 如果测试因环境依赖无法执行，应在交付说明中明确记录原因，不要把未验证的结果表述为测试通过。
