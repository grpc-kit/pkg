package auth

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"

	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/sdk"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
)

// Client 认证鉴权客户端
type Client struct {
	logger *logrus.Entry
	config *Config

	envoy    *envoyProxy
	opaSDK   *sdk.OPA
	opaRego  rego.PreparedEvalQuery
	opaEnvoy authv3.AuthorizationClient

	// opaData 是注入 OPA inmem store 的原始 data 快照（嵌套包名结构）。
	// 由 initOPARego 写入，供测试断言与 P9 Reload 复用。
	opaData map[string]interface{}

	rbacData *rbacv3.RBAC

	// Phase 1 P9：保护 opaRego / opaData / rbacData 的并发读写。
	// 读侧（Allow + 测试断言 opaData）持 RLock；写侧（initOPARego 末尾的赋值
	// 以及由 Reload 触发的重建）持 Lock。其他字段在 NewClient 之后只读，无需上锁。
	mu sync.RWMutex
}

// NewClient 初始化实例
func NewClient(ctx context.Context, config *Config) (*Client, error) {
	var err error

	c := &Client{
		config:   config,
		envoy:    &envoyProxy{},
		logger:   logrus.NewEntry(logrus.New()),
		rbacData: &rbacv3.RBAC{},
	}

	if c.config.OPARego != nil {
		if err = c.initOPARego(ctx); err != nil {
			return nil, err
		}
	}

	if c.config.OPASDK != nil {
		if err = c.initOPASDK(ctx); err != nil {
			return nil, err
		}
	}

	if c.config.OPAEnvoy != nil {
		if err = c.initOPAEnvoy(ctx); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// initOPARego 初始化内置权限验证服务
func (c *Client) initOPARego(ctx context.Context) error {
	dataRego := c.config.OPARego.Rego
	dataRBAC := c.config.OPARego.Data

	// 如果客户端提供的 rego 或 rbac 文件为空包含被注释，则使用框架默认规则
	ncl, err := c.nonCommentLineLength(dataRego)
	if err != nil {
		return err
	}
	if ncl == 0 {
		dataRego = c.config.defaultRego()
	}

	// 动态数据优先级：DataProvider > Data > defaultRBAC()
	// 若 DataProvider 未配置、调用失败或返回为空，则依次降级。
	if c.config.OPARego.DataProvider != nil {
		dynData, provErr := c.config.OPARego.DataProvider(ctx)
		if provErr != nil {
			c.logger.Warnf("opa dynamic data provider error, fallback to static config: %v", provErr)
		} else {
			dynNCL, _ := c.nonCommentLineLength(dynData)
			if dynNCL > 0 {
				dataRBAC = dynData
			} else {
				c.logger.Warn("opa dynamic data provider returned empty data, fallback to static config")
			}
		}
	}

	ncl, err = c.nonCommentLineLength(dataRBAC)
	if err != nil {
		return err
	}
	if ncl == 0 {
		dataRBAC = c.config.defaultRBAC()
	}

	// 需把包头加入进去，如：
	// oneops.syncmi.v1 -> map[oneops:map[syncmi:map[v1:{}]]]
	parts := strings.Split(c.config.PackageName, ".")
	jsonData := make(map[string]interface{})
	currentMap := jsonData
	for _, part := range parts[:len(parts)-1] {
		nextMap := make(map[string]interface{})
		currentMap[part] = nextMap
		currentMap = nextMap
	}

	var jsonRBAC map[string]interface{}
	if err = util.Unmarshal(dataRBAC, &jsonRBAC); err != nil {
		return err
	}

	// 解析 rbac 文件，提供给外部使用。
	// 注意：此处必须先于静态字典合并执行，否则注入的 services/rpc_routes/gateway_routes 等
	// 非 envoy RBAC proto 字段会导致 protojson.Unmarshal 报 unknown field 错误。
	// P9：parseEnvoyRBAC 返回新分配的 *RBAC，避免多个 Reload goroutine 同时往
	// 共享的 c.rbacData 里 unmarshal（protojson + proto.Reset 不是协程安全的）。
	newRBAC, err := c.parseEnvoyRBAC(jsonRBAC)
	if err != nil {
		return err
	}

	// Phase 1 P3：将静态字典合并到 data.<pkg> 命名空间下（与既有 RBAC keys 平级）。
	// 本期仅注入，Rego 模板尚未消费；P5+ 由 input_builder 反查 rpc_routes/gateway_routes，
	// P11+ Rego 通过 services 元数据进行 GRN 匹配。
	// 冲突策略：services / rpc_routes / gateway_routes 为保留键，静态字典优先覆盖。
	if c.config.StaticDict != nil {
		if jsonRBAC == nil {
			jsonRBAC = make(map[string]interface{})
		}
		for k, v := range c.config.StaticDict.BuildOPAData() {
			jsonRBAC[k] = v
		}
	}

	currentMap[parts[len(parts)-1]] = jsonRBAC

	query, err := rego.New(
		rego.Query(fmt.Sprintf("data.%v.allow", c.config.PackageName)),
		rego.Module("auth.rego", string(dataRego)),
		rego.Store(inmem.NewFromObject(jsonData)),
		rego.EnablePrintStatements(true),
	).PrepareForEval(ctx)
	if err != nil {
		return err
	}

	// Phase 1 P9：原子替换 opaRego / opaData / rbacData。Allow 侧持 RLock 读，
	// Reload 通过调用 initOPARego 间接走这条写路径。所有 return err 都发生
	// 在赋值前 ⇒ 失败时旧值自动保持，不需要 try-and-swap。
	c.mu.Lock()
	c.opaRego = query
	c.opaData = jsonData
	c.rbacData = newRBAC
	c.mu.Unlock()

	return nil
}

// initOPASDK 初始化 opa 连接外部统一授权服务
func (c *Client) initOPASDK(ctx context.Context) error {
	opaSDK, err := sdk.New(ctx,
		sdk.Options{
			ID:     c.config.PackageName,
			Config: strings.NewReader(c.config.OPASDK.Config),
		},
	)
	if err != nil {
		return err
	}

	c.opaSDK = opaSDK

	return nil
}

// initOPAEnvoy 初始化 opa 连接外部 envoy_ext_authz_grpc 授权服务
func (c *Client) initOPAEnvoy(ctx context.Context) error {
	addr := c.config.OPAEnvoy.GRPCAddress
	if addr == "" {
		addr = "127.0.0.1:9191"
	}

	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}

	c.opaEnvoy = authv3.NewAuthorizationClient(conn)

	return nil
}

// AuthMetadata 把 http 请求信息转换为 grpc 的 metadata 用于鉴权
func (c *Client) AuthMetadata(ctx context.Context, req *http.Request) context.Context {
	// TODO: 植入请求体，在 grpc auth 中还无法获取 content key
	// DEBUG
	/*
		if (req.Method == http.MethodPut || req.Method == http.MethodPost) &&
			strings.Contains(req.Header.Get("Content-Type"), "application/json") {

			reqBody, err := io.ReadAll(req.Body)
			// c.logger.Infof("error found add body: %v, err: %v, remote addr: %v", string(reqBody), err, req.RemoteAddr)

			if err == nil {
				req.Body = io.NopCloser(bytes.NewBuffer(reqBody))
				if len(reqBody) > 0 {
					ctx = context.WithValue(ctx, "parsed_body", string(reqBody))
				}
			}
		}
	*/

	return c.envoy.extractHTTPHeader(ctx, req)
}

// Allow 是否满足策略允许访问
func (c *Client) Allow(ctx context.Context) (bool, error) {
	req, err := c.envoy.getCheckRequest(ctx)
	if err != nil {
		return false, err
	}

	input, err := c.envoy.requestToInput(ctx, req)
	if err != nil {
		return false, err
	}

	// Phase 1 P6：在保留旧 envoy 风格字段（attributes / parsed_path）的前提下，
	// 追加协议无关的 input.grpc_kit 子树，供 P8 起新 Rego 消费 `input.grpc_kit.action_id`。
	// 反查顺序：先 gRPC method（拦截器栈典型路径），未命中再用 envoy 请求里的
	// HTTP method + path 走 GatewayRoutes 字面匹配（纯 HTTP handler 路径）。
	// 旧 Rego 仍以 `input.parsed_path[0]` / `input.attributes.*` 工作，不读 grpc_kit 字段。
	c.mergeGrpcKitInput(ctx, input, req)

	c.logger.Debugf("opa auth input: %s", string(util.MustMarshalJSON(input)))

	if c.config.OPARego != nil {
		var rs rego.ResultSet

		// Phase 1 P9：读 opaRego 持 RLock；Reload 期间会被短暂阻塞，
		// 但 rego.PreparedEvalQuery.Eval 本身是协程安全的，无需在 Eval 中持续持锁，
		// 因此把 query 拷贝到栈上再释放锁，最大化并发度。
		c.mu.RLock()
		query := c.opaRego
		c.mu.RUnlock()

		rs, err = query.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			return false, err
		}

		if rs.Allowed() == false {
			return false, err
		}
	}

	if c.config.OPASDK != nil {
		var dr *sdk.DecisionResult

		dr, err = c.opaSDK.Decision(ctx,
			sdk.DecisionOptions{
				Path:  fmt.Sprintf("%v/allow", strings.Replace(c.config.PackageName, ".", "/", -1)),
				Input: input,
			},
		)
		if err != nil {
			return false, err
		}

		allow, ok := dr.Result.(bool)
		if !ok || !allow {
			return false, err
		}
	}

	if c.config.OPAEnvoy != nil {
		var resp *authv3.CheckResponse
		resp, err = c.opaEnvoy.Check(ctx, req)
		if err != nil {
			return false, err
		}
		if resp.GetStatus().Code != 0 {
			return false, err
		}
	}

	return true, nil
}

// mergeGrpcKitInput 把 input_builder 反查得到的 subject + grpc_kit 子树
// 合并到 envoy 风格的 input map 中（Phase 1 P6）。
//
// 设计要点：
//
//   - **追加而非覆盖**：仅写入 `input["subject"]` 与 `input["grpc_kit"]` 两个顶层键，
//     旧 `attributes` / `parsed_path` / `parsed_query` 保留不动 —— 旧 Rego 完全兼容。
//   - **协议无关反查**：先用 `grpc.Method(ctx)` 走 RPCRoutes（拦截器栈典型路径），
//     未命中再用 envoy 已还原的 HTTP method+path 走 GatewayRoutes 字面匹配。
//   - **StaticDict 缺省时仍写空 grpc_kit**：保持 Rego 引用 `input.grpc_kit.action_id`
//     不会 undefined；service/action/action_id 全为空字符串 ⇒ 旧规则不命中、新规则可拒绝。
//   - **永不返回 error**：反查失败不应阻塞鉴权决策；OPA 仍会按现有规则继续评估。
func (c *Client) mergeGrpcKitInput(ctx context.Context, input map[string]interface{}, req *authv3.CheckRequest) {
	dict := c.config.StaticDict

	// 路径 1：gRPC method 反查（grpc.Method(ctx) → /<svc>/<method> → RPCRoutes）
	gk := FromGRPCContext(ctx, dict).GrpcKit

	// 路径 2：envoy 已还原的 HTTP method+path 走 GatewayRoutes 字面匹配
	// 仅在路径 1 未命中且 envoy req 含 HTTP 字段时尝试，避免覆盖 gRPC 反查结果。
	if gk.ActionID == "" && req != nil {
		if http := req.GetAttributes().GetRequest().GetHttp(); http != nil {
			path := http.GetPath()
			method := http.GetMethod()
			if path != "" && dict != nil {
				// 复用 P5 的 FromHTTPRequest 需要 *http.Request；为避免反复构造，
				// 直接走 GatewayRoutes 字面匹配（与 FromHTTPRequest 等价语义，
				// 仅去掉 url 解析；envoy 拿到的 path 已是裸路径或带 query）。
				gk = lookupGatewayRoute(dict, method, path)
			}
		}
	}

	// 始终写入两键，便于 Rego 用空串判定"未注册动作"。
	input["subject"] = map[string]any{}
	input["grpc_kit"] = map[string]any{
		"service":   gk.Service,
		"action":    gk.Action,
		"action_id": gk.ActionID,
	}
}

// lookupGatewayRoute 与 FromHTTPRequest 同语义，但接受裸字符串避免构造 *http.Request。
// envoy 还原的 path 可能含 querystring（如 "/ping?x=1"），这里仅按 "?" 之前的路径段做字面匹配。
func lookupGatewayRoute(dict *StaticDict, method, rawPath string) GrpcKit {
	if dict == nil {
		return GrpcKit{}
	}
	path := rawPath
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	upper := strings.ToUpper(method)
	for _, r := range dict.GatewayRoutes {
		if !strings.EqualFold(r.Method, upper) {
			continue
		}
		if r.PathTemplate != path {
			continue
		}
		return splitActionID(r.ActionID)
	}
	return GrpcKit{}
}

// WithLoggerOption 设置日志记录器
func (c *Client) WithLoggerOption(logger *logrus.Entry) *Client {
	if logger != nil {
		c.logger = logger
	}

	return c
}

// Close 关闭释放资源
func (c *Client) Close(ctx context.Context) {
	if c.opaSDK != nil {
		c.opaSDK.Stop(ctx)
	}
}

// https://pkg.go.dev/github.com/envoyproxy/go-control-plane@v0.12.0/envoy/config/rbac/v3#RBAC
func (c *Client) demoDataOPARBAC(ctx context.Context) (*rbacv3.RBAC, error) {
	data := &rbacv3.RBAC{
		Action:   rbacv3.RBAC_ALLOW,
		Policies: make(map[string]*rbacv3.Policy),
	}

	role1 := &rbacv3.Policy{
		Permissions: []*rbacv3.Permission{
			{
				Rule: &rbacv3.Permission_UrlPath{
					UrlPath: &matcherv3.PathMatcher{
						Rule: &matcherv3.PathMatcher_Path{
							Path: &matcherv3.StringMatcher{
								MatchPattern: &matcherv3.StringMatcher_Exact{
									Exact: "/",
								},
							},
						},
					},
				},
			},
		},
		Principals: []*rbacv3.Principal{
			{
				Identifier: &rbacv3.Principal_Any{
					Any: true,
				},
			},
		},
	}

	data.Policies["role-public"] = role1

	return data, nil
}

func (c *Client) nonCommentLineLength(body []byte) (int, error) {
	if len(body) == 0 {
		return 0, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(body))
	nonCommentLines := 0

	for scanner.Scan() {
		line := scanner.Text()

		// 去除行首空白字符
		line = strings.TrimSpace(line)

		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 非注释行计数
		nonCommentLines++
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return nonCommentLines, nil
}

// parseEnvoyRBAC 将 yaml/json 反序列化后的 map 转为 envoy RBAC proto。
//
// P9：返回新分配的 *rbacv3.RBAC，调用方负责在持锁后赋给 c.rbacData。
// 原因：protojson.Unmarshal 内部需先 proto.Reset(target)，如果 target 是跨多个
// goroutine 共享的同一个 *RBAC 指针（顶层 c.rbacData），会与同时在读的
// ProtoReflect 调用出现 atomic.LoadPointer / typedmemmove 竞争。改为为每次
// Reload 新建一个 target 后原子替换，可彻底避免读写同一个对象。
func (c *Client) parseEnvoyRBAC(mapData map[string]interface{}) (*rbacv3.RBAC, error) {
	// 因本地配置使用 yaml 格式，故需要先转换为 json
	rawBody, err := json.Marshal(mapData)
	if err != nil {
		return nil, fmt.Errorf("marshal rbac data to json err: %w", err)
	}

	// 这里必须使用 protojson 转换为 proto 格式
	//
	// P8：使用 DiscardUnknown=true 容忍非 envoy RBAC 字段。
	// 历史背景：dbloader（P7+）注入的 policies/roles/subjects 三段顶层键、以及
	// static dict（P3）注入的 services/rpc_routes/gateway_routes 都不属于 envoy RBAC proto schema。
	// 旧版通过"先 parseEnvoyRBAC 再合并 static dict"的顺序绕开，但 DataProvider 路径无法
	// 绕开（其产物在 unmarshal jsonRBAC 时就被消费）；放宽 DiscardUnknown 是最干净的根因解，
	// 既允许 dbloader 直接接入，也使现有合并顺序失误不再致命崩溃。
	// 安全边界：envoy RBAC 自身字段仍按 proto schema 严格解析（类型不匹配仍报错），
	// 仅未知字段被忽略，不会引入静默解析错误。
	target := &rbacv3.RBAC{}
	if err = (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(rawBody, target); err != nil {
		return nil, fmt.Errorf("unmarshal rbac data to proto err: %w", err)
	}

	return target, nil
}

func (c *Client) GetRBACData() *rbacv3.RBAC {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rbacData
}
