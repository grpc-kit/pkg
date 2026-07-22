package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/grpc-kit/pkg/admin/openapiconfig"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/genproto/googleapis/api/serviceconfig"
)

// toSnakeCase 将 PascalCase 字符串转换为 snake_case。
//
// 转换规则：
//   - 在小写字母与大写字母之间插入下划线
//   - 连续的大写字母视为一个单词（保留）
//   - 全部结果转为小写
//
// 示例：
//   - "OneopsNetdev" -> "oneops_netdev"
//   - "DeleteSwitchAdminUser" -> "delete_switch_admin_user"
//   - "UserService" -> "user_service"
//   - "ID" -> "id"
//   - "URLPath" -> "urlpath"（连续大写会粘合；通常不应作为单字输入）
//
// 空字符串返回空字符串。
func toSnakeCase(s string) string {
	if s == "" {
		return ""
	}

	runes := []rune(s)
	out := make([]rune, 0, len(runes)+4)
	for i, r := range runes {
		if i > 0 && isUpper(r) && !isUpper(runes[i-1]) {
			out = append(out, '_')
		}
		out = append(out, toLower(r))
	}
	return string(out)
}

func isUpper(r rune) bool { return r >= 'A' && r <= 'Z' }
func toLower(r rune) rune {
	if isUpper(r) {
		return r + ('a' - 'A')
	}
	return r
}

// parseSelector 解析 gRPC selector 字符串，提取 service 名和 method 名。
//
// selector 格式（参考 google.api.HttpRule.selector）：
//
//	"default.api.<package>.<service>.<Method>"
//
// 期望至少 7 段：["default", "api", "<package>", "<subpkg>", "<version>", "<service>", "<method>"]
// 实际工程中常见段数为 6 或 7，parts[5] 通常为 service，parts[6] 通常为 method。
// 本实现采用 parts[5]=service, parts[6]=method 约定，与 admin 端 ListServiceActions 一致。
//
// 当段数不足时返回 ("", "")，调用方应跳过该 selector。
func parseSelector(selector string) (serviceName, methodName string) {
	if selector == "" {
		return "", ""
	}

	parts := splitDots(selector)
	// 支持两种格式：
	//   7 段: "package.api.known.admin.v1.Service.Method" → parts[5]=Service, parts[6]=Method
	//   6 段: "package.api.test.v1.Service.Method"      → parts[4]=Service, parts[5]=Method
	switch len(parts) {
	case 7:
		return parts[5], parts[6]
	case 6:
		return parts[4], parts[5]
	default:
		return "", ""
	}
}

// splitDots 按 '.' 分割字符串。空段会被保留（与 strings.Split 一致）。
func splitDots(s string) []string {
	out := make([]string, 0, 8)
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// httpRuleMethodAndPath 提取 HttpRule 的 HTTP method 与 path。
//
// 优先匹配顺序：GET > PUT > POST > DELETE > PATCH > Custom。
// 其中 Custom 使用 Kind 与 Path 字段，method 通过 rule.GetCustom().GetKind() 获取。
// 若 rule 为 nil 或所有 method 均为空，返回 ("", "")。
//
// 与 admin/rpc_services.go 中的 httpRulePrimaryPathTemplate 不同：
// 该函数同时返回 method 信息，供 AutoBridge 构建 MCP Tool 使用。
func httpRuleMethodAndPath(rule *annotations.HttpRule) (method, path string) {
	if rule == nil {
		return "", ""
	}

	switch {
	case rule.GetGet() != "":
		return "GET", rule.GetGet()
	case rule.GetPut() != "":
		return "PUT", rule.GetPut()
	case rule.GetPost() != "":
		return "POST", rule.GetPost()
	case rule.GetDelete() != "":
		return "DELETE", rule.GetDelete()
	case rule.GetPatch() != "":
		return "PATCH", rule.GetPatch()
	default:
		if custom := rule.GetCustom(); custom != nil && custom.GetPath() != "" {
			return custom.GetKind(), custom.GetPath()
		}
	}

	return "", ""
}

// formatDescription 将 tags 与 swagger description 拼接为最终 MCP Tool description。
//
// 格式：
//   - tags 为空：直接返回 description
//   - tags 非空：返回 "[tag1, tag2] description"
//
// 当 description 为空但 tags 非空时，仅返回 "[tag1, tag2]"（不附加多余空白）。
func formatDescription(tags []string, description string) string {
	if len(tags) == 0 {
		return description
	}

	prefix := "["
	for i, t := range tags {
		if i > 0 {
			prefix += ", "
		}
		prefix += t
	}
	prefix += "]"

	if description == "" {
		return prefix
	}
	return prefix + " " + description
}

// AutoBridge 将已注册的 gRPC 方法自动转换为 MCP Tools。
//
// 工作流程：
//  1. 构建 selector -> swagger Operation 映射表（用于提取 description / tags）
//  2. 遍历 gatewayCfg.Http.GetRules()，对每个 HttpRule：
//     - 解析 selector 提取 serviceName / methodName
//     - 转换为 snake_case 命名
//     - 处理主绑定 + AdditionalBindings（每个 binding 独立 tool + 后缀）
//     - 从 path template 提取 path 参数构建 input schema
//     - 通过 server.AddTool 注册
//  3. 每个 Tool 的 handler 将请求转发到 httpBaseURL + path（替换 path 参数），
//     并通过 httpClient.Do 发送实际 HTTP 请求。
//
// nil 保护：
//   - server == nil: 返回 nil
//   - gatewayCfg == nil: 返回 nil（无规则可遍历）
//   - swaggerCfg == nil: 仍注册 tool，但 description 为空
//   - httpClient == nil: 使用 http.DefaultClient 兜底
//
// AutoBridge 永远不会因配置缺失而 panic；遇到无法识别的规则时记录警告并跳过。
func AutoBridge(
	server *mcp.Server,
	connFn GRPCConnFunc,
	httpClient *http.Client,
	httpBaseURL string,
	gatewayCfg *serviceconfig.Service,
	swaggerCfg *openapiconfig.OpenAPIConfig,
	assets fs.FS,
	swaggerAssetName string,
	allowedTags []string,
	logger *logrus.Entry,
) error {
	_ = connFn // 暂未使用，预留 gRPC reflection 优化
	if server == nil {
		return nil
	}
	if logger == nil {
		logger = logrus.StandardLogger().WithField("component", "mcp-bridge")
	}
	if gatewayCfg == nil {
		return nil
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	logger.Infoln("http base url:", httpBaseURL)

	// 加载 swagger.json（Phase 6）：失败/缺失时 swDoc=nil，op 查找恒为 nil，
	// buildInputSchemaFromSwagger 降级为仅 path 参数（Phase 5 行为），不报错。
	swDoc, _ := loadSwaggerDoc(assets, swaggerAssetName)
	var opIndex swaggerOpIndex
	if swDoc != nil {
		opIndex = buildSwaggerOpIndex(swDoc)
	}

	// selector -> openapiv2 方法文档（summary/description/tags 兜底）
	docMap := buildSelectorDocMap(swaggerCfg)

	// allowedTags 非空时构建快速查找集合（白名单，OR 语义）
	allowedSet := make(map[string]struct{}, len(allowedTags))
	for _, t := range allowedTags {
		allowedSet[t] = struct{}{}
	}

	rules := gatewayCfg.GetHttp().GetRules()
	registered := make(map[string]struct{}, len(rules))

	for _, rule := range rules {
		if rule == nil {
			continue
		}
		serviceName, methodName := parseSelector(rule.GetSelector())
		if serviceName == "" || methodName == "" {
			continue
		}

		// Tool name 仅取方法名（snake_case），不加服务名前缀。
		// grpc-kit 单进程只跑一个业务微服务，AutoBridge 只处理该微服务的 gateway
		// 配置（不含 admin），所有 tool 同属一个 service，服务名前缀是冗余噪音。
		// serviceName 仍保留用于上方的空值 guard（检测 malformed selector）。
		// 多 service 场景下 method 重名由 uniqueToolName 追加 _2/_3 兜底。
		baseName := toSnakeCase(methodName)

		// 收集主绑定 + AdditionalBindings
		bindings := collectHttpBindings(rule)
		if len(bindings) == 0 {
			continue
		}

		for bindingIdx, binding := range bindings {
			httpMethod, pathTemplate := httpRuleMethodAndPath(binding)
			if httpMethod == "" || pathTemplate == "" {
				continue
			}

			op := lookupSwaggerOp(opIndex, httpMethod, pathTemplate)
			// summary/description/tags 优先取 swagger op，兜底 openapiv2 docMap
			summary, description, tags := lookupOpDocs(op, docMap, rule.GetSelector())

			// tag 白名单过滤：allowedTags 非空时，tags 必须命中至少一个才注册。
			// 未命中（含 tags 为空）的 binding 跳过，不暴露为 MCP tool。
			if len(allowedSet) > 0 && !hasAllowedTag(tags, allowedSet) {
				continue
			}

			bodyField := binding.GetBody()

			// 主绑定（bindingIdx == 0）使用 baseName；
			// AdditionalBindings（bindingIdx > 0）追加路径后缀以区分。
			var toolName string
			if bindingIdx == 0 {
				toolName = baseName
			} else {
				suffix := sanitizePathSuffix(pathTemplate, httpMethod)
				if suffix == "" {
					suffix = "binding" + itoa2(bindingIdx)
				}
				toolName = baseName + "__" + suffix
			}
			toolName = uniqueToolName(toolName, registered)
			inputSchema := buildInputSchemaFromSwagger(op, bodyField, pathTemplate, swDoc)
			desc := formatDescription(tags, mergeSummaryDescription(summary, description))

			// 捕获循环变量
			method := httpMethod
			tmpl := pathTemplate
			bf := bodyField
			opCapture := op
			tn := toolName
			handler := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return bridgeHandler(ctx, req, httpClient, httpBaseURL, method, tmpl, bf, opCapture, tn, logger)
			}

			server.AddTool(&mcp.Tool{
				Name:        toolName,
				Description: desc,
				InputSchema: inputSchema,
				Annotations: buildToolAnnotations(httpMethod),
			}, handler)
		}
	}

	return nil
}

// bridgeHandler 实际执行 HTTP 调用的 handler。
//
// 调试日志：使用注入的 logger（component=mcp-bridge，由 cfg 层传入），在全局 log_level=debug
// 时按阶段打印转发到 grpc-gateway 的请求/响应日志（tool 名、method、URL、body、状态码、
// 耗时），用于排查 MCP tool 调用阻塞点。日志按以下阶段输出，缺失的那一段即指示阻塞位置：
//   - invoked:           handler 被调用（若缺失 -> 阻塞在 SDK session / 中间件）
//   - forwarding:        请求已构造，即将发送到 gateway（若缺失 -> 阻塞在请求构造）
//   - gateway responded: httpClient.Do 返回（若缺失 -> 阻塞在 HTTP 调用，含超时）
//   - response body:     响应体已读取（若缺失 -> 阻塞在读响应体）
func bridgeHandler(
	ctx context.Context,
	req *mcp.CallToolRequest,
	httpClient *http.Client,
	httpBaseURL, httpMethod, pathTemplate, bodyField string,
	op *swaggerOperation,
	toolName string,
	logger *logrus.Entry,
) (*mcp.CallToolResult, error) {
	args := parseArguments(req.Params.Arguments)

	logger.Infof("tool=%s invoked method=%s args=%s\n",
		toolName, httpMethod, truncateForLog(mustJSON(args), debugMaxBodyLen))

	// 替换 path 参数
	path, missing := substitutePathParams(pathTemplate, args)
	if missing != "" {
		logger.Debugf("tool=%s abort: missing path parameter %q", toolName, missing)
		return errorResult("missing path parameter: " + missing), nil
	}

	// 构建完整 URL（含 query 参数；op 分类，命名即 grpc-gateway 期望）
	base := strings.TrimRight(httpBaseURL, "/")
	url := appendQueryParams(base+path, pathTemplate, op, args)

	var (
		bodyReader io.Reader
		contentSet bool
		bodyBytes  []byte
	)
	// 非幂等方法（POST/PATCH）或有 body 映射（PUT 等）时构建请求体
	if !isIdempotentMethod(httpMethod) || bodyField != "" {
		body, ok := buildRequestBody(args, op, pathTemplate, bodyField)
		if ok {
			bodyBytes = body
			bodyReader = bytes.NewReader(body)
			contentSet = true
		}
	}

	httpReq, err := http.NewRequestWithContext(ctx, httpMethod, url, bodyReader)
	if err != nil {
		logger.Debugf("tool=%s abort: build request error: %v", toolName, err)
		return errorResult("build request: " + err.Error()), nil
	}
	if contentSet {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	// 透传认证：把 MCP 客户端原始 Authorization header 设置到 outgoing HTTP 请求上，
	// 使 gateway 能通过既有 optionWithMetada 机制把 Authorization 透传给 gRPC 服务端
	// 进行鉴权与审计。
	//
	// 通过 req.Extra.Header 获取 -- MCP SDK 在 servePOST 中会把当前 POST 请求的
	// HTTP headers 注入到 RequestExtra.Header（见 SDK streamable.go）。这是最可靠的
	// 方式，因为每个 tool call 请求的 headers 都是独立的，不受 stateful session
	// 复用的影响。
	//
	// 注：middleware.go 中 NewAuthMiddleware 也通过 context 注入 Authorization
	// （ContextWithAuthHeader/AuthHeaderFromContext），作为未来扩展点（如 OPA per-tool
	// 鉴权中间件链）预留。但 bridgeHandler 不依赖 context 路径，避免 pkg/mcp/tools
	// -> pkg/mcp 的测试期循环依赖。
	authSet := false
	if req != nil && req.Extra != nil && req.Extra.Header != nil {
		if authHeader := req.Extra.Header.Get("Authorization"); authHeader != "" {
			httpReq.Header.Set("Authorization", authHeader)
			authSet = true
		}
	}

	// 发送前打点：若此日志出现而「gateway responded」未出现，说明阻塞在 httpClient.Do
	// （gateway 未响应 / 代理劫持 / TLS 握手卡住等）。httpClient.Timeout=30s 兜底，
	// 超时后会打印 "http call failed after 30s"。
	logger.Debugf("tool=%s forwarding to gateway: %s %s body=%s auth=%v",
		toolName, httpMethod, url, truncateForLog(string(bodyBytes), debugMaxBodyLen), authSet)

	start := time.Now()
	resp, err := httpClient.Do(httpReq)
	callDur := time.Since(start)
	if err != nil {
		logger.Debugf("tool=%s http call failed after %v: %v", toolName, callDur, err)
		return errorResult("http call: " + err.Error()), nil
	}
	defer resp.Body.Close()

	logger.Debugf("tool=%s gateway responded status=%d after %v", toolName, resp.StatusCode, callDur)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Debugf("tool=%s read response error after %v: %v", toolName, time.Since(start), err)
		return errorResult("read response: " + err.Error()), nil
	}

	logger.Debugf("tool=%s response body (%d bytes): %s",
		toolName, len(respBody), truncateForLog(string(respBody), debugMaxBodyLen))

	if resp.StatusCode >= 400 {
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{
				&mcp.TextContent{Text: mustJSON(map[string]any{
					"status": resp.StatusCode,
					"body":   string(respBody),
				})},
			},
		}, nil
	}

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{Text: string(respBody)},
		},
	}, nil
}

// ----------------------------------------------------------------------------
// 转发调试日志
//
// bridgeHandler 转发到 grpc-gateway 的请求/响应调试日志使用由 cfg 层注入的 logger
// （pkg/cfg/logger.go 的 initDebugger 统一配置 level/format/output），在全局
// log_level=debug 时输出。按 invoked / forwarding / gateway responded / response
// body 四阶段打印（含耗时），缺失的那一段即指示阻塞位置。详见 bridgeHandler 文档注释。
// ----------------------------------------------------------------------------

// debugMaxBodyLen 限制调试日志中 body 文本的长度，避免超长 body 撑爆日志。
const debugMaxBodyLen = 2048

// truncateForLog 截断字符串到 n 字节，超出则追加 "...(truncated, len=N)"。
func truncateForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + fmt.Sprintf("...(truncated, len=%d)", len(s))
}

// errorResult 构造错误返回结果。
func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{
			&mcp.TextContent{Text: mustJSON(map[string]string{"error": msg})},
		},
	}
}

// isIdempotentMethod 判断 HTTP method 是否为幂等（GET/HEAD/OPTIONS/DELETE/PUT）。
// 幂等方法的参数通过 query string 传递，否则通过 body 传递。
func isIdempotentMethod(method string) bool {
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS", "DELETE", "PUT":
		return true
	}
	return false
}

// ptrBool 返回 b 的地址，用于 *bool 类型的 ToolAnnotations 字段。
func ptrBool(b bool) *bool { return &b }

// buildToolAnnotations 根据 HTTP method 推断 MCP ToolAnnotations 语义标注。
//
// 映射规则（Phase 8 Layer 1）：
//   - GET / HEAD / OPTIONS：只读 + 幂等（ReadOnlyHint=true, IdempotentHint=true, DestructiveHint=false）
//   - PUT：幂等写入（IdempotentHint=true, DestructiveHint=false）
//   - DELETE：幂等破坏性删除（IdempotentHint=true, DestructiveHint=true）
//   - POST / PATCH / 其他：非幂等写入（DestructiveHint=false）
//
// OpenWorldHint 保持 nil：AutoBridge 通过本地 gateway 调用，不与外部世界直接交互。
// DestructiveHint 显式设 false（而非 nil）以覆盖 SDK 默认值 true。
func buildToolAnnotations(httpMethod string) *mcp.ToolAnnotations {
	switch strings.ToUpper(httpMethod) {
	case "GET", "HEAD", "OPTIONS":
		return &mcp.ToolAnnotations{
			ReadOnlyHint:    true,
			IdempotentHint:  true,
			DestructiveHint: ptrBool(false),
		}
	case "PUT":
		return &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			IdempotentHint:  true,
			DestructiveHint: ptrBool(false),
		}
	case "DELETE":
		return &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			IdempotentHint:  true,
			DestructiveHint: ptrBool(true),
		}
	default: // POST, PATCH, 自定义方法
		return &mcp.ToolAnnotations{
			ReadOnlyHint:    false,
			IdempotentHint:  false,
			DestructiveHint: ptrBool(false),
		}
	}
}

// pathParamRegex 匹配 path template 中的 {param} 占位符。
var pathParamRegex = regexp.MustCompile(`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`)

// swaggerMethod 描述 OpenAPI 方法配置。
type swaggerMethod struct {
	summary     string
	description string
	tags        []string
}

// buildSelectorDocMap 构建 selector -> swaggerMethod 映射表。
//
// 从 OpenAPIConfig.OpenapiOptions.Method 中读取（key 格式为 "service/method"）。
// swaggerCfg 为 nil 时返回空映射（AutoBridge 仍可注册 tool，但 description 为空）。
func buildSelectorDocMap(swaggerCfg *openapiconfig.OpenAPIConfig) map[string]swaggerMethod {
	out := make(map[string]swaggerMethod)
	if swaggerCfg == nil {
		return out
	}

	openapi := swaggerCfg.GetOpenapiOptions()
	if openapi == nil {
		return out
	}

	for _, opt := range openapi.GetMethod() {
		if opt == nil || opt.GetOption() == nil {
			continue
		}
		out[opt.GetMethod()] = swaggerMethod{
			summary:     opt.GetOption().GetSummary(),
			description: opt.GetOption().GetDescription(),
			tags:        opt.GetOption().GetTags(),
		}
	}
	return out
}

// lookupSwaggerDoc 已被 lookupOpDocs（swagger 优先 + docMap 兜底）取代并删除。
// docMap 的兜底逻辑现由 lookupOpDocs(op=nil) 路径提供。

// mergeSummaryDescription 合并 summary 与 description：summary 优先。
func mergeSummaryDescription(summary, description string) string {
	if summary != "" {
		return summary
	}
	return description
}

// hasAllowedTag 判断 operation 的 tags 是否命中白名单集合（OR 语义）。
// tags 为空时返回 false（白名单语义：未标注的不暴露）。
func hasAllowedTag(tags []string, allowedSet map[string]struct{}) bool {
	for _, t := range tags {
		if _, ok := allowedSet[t]; ok {
			return true
		}
	}
	return false
}

// collectHttpBindings 收集主绑定 + 所有 AdditionalBindings 为统一列表。
// 跳过 nil 绑定。
func collectHttpBindings(rule *annotations.HttpRule) []*annotations.HttpRule {
	if rule == nil {
		return nil
	}

	bindings := make([]*annotations.HttpRule, 0, 1+len(rule.GetAdditionalBindings()))
	bindings = append(bindings, rule)
	for _, b := range rule.GetAdditionalBindings() {
		if b != nil {
			bindings = append(bindings, b)
		}
	}
	return bindings
}

// uniqueToolName 确保 tool name 在 registered 集合中唯一。
//
// 处理流程：
//  1. 截断到 128 字符
//  2. 替换不合规字符
//  3. 极小概率冲突时追加 _2, _3 ...
//
// 输入 candidate 已由调用方决定（主绑定用 baseName，AdditionalBindings 用 baseName + __suffix）。
func uniqueToolName(candidate string, registered map[string]struct{}) string {
	// 截断到 128 字符（MCP 规范上限）
	const maxLen = 128
	if len(candidate) > maxLen {
		candidate = candidate[:maxLen]
	}

	// 替换任何不合规字符
	candidate = sanitizeToolName(candidate)

	// 去重
	for i := 0; ; i++ {
		if _, exists := registered[candidate]; !exists {
			registered[candidate] = struct{}{}
			return candidate
		}
		// 极小概率冲突：追加 _2, _3 ...
		suffix := "_" + itoa2(i+2)
		base := candidate
		if len(base)+len(suffix) > maxLen {
			base = base[:maxLen-len(suffix)]
		}
		candidate = base + suffix
	}
}

// sanitizePathSuffix 从 path template 提取后缀。
//
// 规则：取 path 末段（非 "{var}" 时），去前导 "/"，替换非字母数字为 "_"。
// 例如：
//   - "/v1/auth/login" + "POST" -> "login"
//   - "/v1/items/{id}" + "GET" -> "items_id"
//
// 用于当 HttpRule 有 AdditionalBindings 时区分同名 tool。
func sanitizePathSuffix(pathTemplate, httpMethod string) string {
	segments := strings.Split(strings.Trim(pathTemplate, "/"), "/")
	if len(segments) == 0 {
		return ""
	}

	// 取最后一个非参数段作为后缀基础
	var picked string
	for i := len(segments) - 1; i >= 0; i-- {
		s := segments[i]
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			continue
		}
		picked = s
		break
	}

	if picked == "" {
		// 全是参数：用 method 作后缀
		return strings.ToLower(httpMethod)
	}

	// 替换非字母数字
	var b strings.Builder
	for _, r := range strings.ToLower(picked) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}

// itoa2 将非负整数转换为字符串（避免引入 strconv）。
func itoa2(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// sanitizeToolName 替换 tool name 中的不合规字符。
//
// MCP 规范允许字符：[a-zA-Z0-9_-.]。其他字符替换为 "_"。
func sanitizeToolName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_' || r == '-' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// buildInputSchema 根据 path template 构造 input JSON Schema。
//
// 始终返回 {"type":"object", "properties":{...}, "required":[...]}
// 其中 properties 包含所有 path 参数（string 类型）。
//
// 返回 map[string]any 而非 json.RawMessage，因为 MCP SDK 的 Server.AddTool
// 会用 remarshal 将 InputSchema 解析回 map[string]any，要求必须是 JSON object
// 形式（带 "type":"object"）。
func buildInputSchema(pathTemplate string) map[string]any {
	matches := pathParamRegex.FindAllStringSubmatch(pathTemplate, -1)
	if len(matches) == 0 {
		return map[string]any{"type": "object"}
	}

	props := make(map[string]map[string]string, len(matches))
	required := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))

	for _, m := range matches {
		name := m[1]
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		props[name] = map[string]string{"type": "string"}
		required = append(required, name)
	}

	schema := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

// parseArguments 将 CallToolRequest 的 arguments 解析为 map[string]json.RawMessage。
//
// arguments 为 nil 或不是 JSON object 时返回空 map。
func parseArguments(raw json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage)
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out
	}
	return out
}

// substitutePathParams 替换 path template 中的 {param} 占位符。
//
// 缺失参数时返回 ("", missingParamName)；空参数视为缺失。
func substitutePathParams(pathTemplate string, args map[string]json.RawMessage) (string, string) {
	missing := ""
	out := pathParamRegex.ReplaceAllStringFunc(pathTemplate, func(token string) string {
		if missing != "" {
			return token
		}
		// 去掉 { 和 }
		name := token[1 : len(token)-1]
		raw, ok := args[name]
		if !ok {
			missing = name
			return token
		}
		// 去掉 JSON 字符串引号
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			missing = name
			return token
		}
		if s == "" {
			missing = name
			return token
		}
		return s
	})
	if missing != "" {
		return "", missing
	}
	return out, ""
}

// extractBodyArgs 已被 buildRequestBody（Phase 6）替代并删除。
// 历史实现见 git history；新实现按 swagger 参数分类构建 flat/标量 body，见 buildRequestBody。

// ----------------------------------------------------------------------------
// Phase 6: Swagger JSON 解析（Step 1-2）
//
// AutoBridge 的 Input Schema 数据源从 path 模板扩展为完整 Swagger 2.0 文档。
// 以下类型与函数负责加载 swagger.json、建立 (httpMethod, path) 操作索引、
// 递归 inline 展开 $ref（自包含 JSON Schema，含 title->description 提升与
// 深度/环保护）。本阶段仅新增能力，尚未接入 AutoBridge 主循环（Step 3+）。
// ----------------------------------------------------------------------------

// swaggerDoc 是 Swagger 2.0 文档的轻量表示，仅保留 AutoBridge 所需字段。
//
//   - Paths: path -> method(小写, 如 "get"/"post") -> operation
//   - Definitions: definition 名 -> 原始 JSON Schema（按需懒解析，支持 $ref 递归展开）
type swaggerDoc struct {
	Paths       map[string]map[string]*swaggerOperation `json:"paths"`
	Definitions map[string]json.RawMessage              `json:"definitions"`
}

// swaggerOperation 对应 OpenAPI 2.0 的 Operation Object（仅保留所需字段）。
type swaggerOperation struct {
	OperationID string             `json:"operationId"`
	Summary     string             `json:"summary"`
	Description string             `json:"description"`
	Tags        []string           `json:"tags"`
	Parameters  []swaggerParameter `json:"parameters"`
}

// swaggerParameter 对应 OpenAPI 2.0 的 Parameter Object。
//
//   - In: "path" | "query" | "body"（formData/header 不适用于 grpc-gateway 产物）
//   - Type/Format/Items: path/query 基本类型及其数组元素
//   - Schema: body 参数的 schema（$ref 指向请求消息 definition，或 inline）
type swaggerParameter struct {
	Name        string          `json:"name"`
	In          string          `json:"in"`
	Required    bool            `json:"required"`
	Description string          `json:"description"`
	Type        string          `json:"type"`
	Format      string          `json:"format"`
	Items       json.RawMessage `json:"items"`
	Schema      json.RawMessage `json:"schema"`
}

// swaggerOpIndex 以 (HTTP 方法大写, path) 为键索引操作，便于按 binding 快速查找。
type swaggerOpIndex map[string]map[string]*swaggerOperation

// loadSwaggerDoc 从 assets FS 读取并解析 openapi/<name>.swagger.json。
//
// assets 为 nil、文件缺失或解析失败时返回 (nil, error)；调用方应降级为
// 仅 path 参数的旧行为（见 §5.1）。definitions 保留为原始字节，按需懒解析。
func loadSwaggerDoc(assets fs.FS, name string) (*swaggerDoc, error) {
	if assets == nil {
		return nil, fmt.Errorf("assets fs is nil")
	}
	f, err := assets.Open("openapi/" + name + ".swagger.json")
	if err != nil {
		return nil, fmt.Errorf("open swagger %q: %w", name, err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read swagger %q: %w", name, err)
	}

	doc := &swaggerDoc{}
	if err := json.Unmarshal(data, doc); err != nil {
		return nil, fmt.Errorf("unmarshal swagger %q: %w", name, err)
	}
	return doc, nil
}

// buildSwaggerOpIndex 遍历 doc.Paths 构建 (method, path) 索引。
//
// method 取键名并 ToUpper；同一 (method, path) 仅保留一个操作
// （Swagger 规范保证唯一）。doc 为 nil 时返回空索引。
func buildSwaggerOpIndex(doc *swaggerDoc) swaggerOpIndex {
	idx := swaggerOpIndex{}
	if doc == nil || doc.Paths == nil {
		return idx
	}
	for path, methods := range doc.Paths {
		if methods == nil {
			continue
		}
		for methodLC, op := range methods {
			if op == nil {
				continue
			}
			method := strings.ToUpper(methodLC)
			if idx[method] == nil {
				idx[method] = make(map[string]*swaggerOperation)
			}
			idx[method][path] = op
		}
	}
	return idx
}

// lookupSwaggerOp 按 (httpMethod, pathTemplate) 查找操作。未命中返回 nil。
func lookupSwaggerOp(idx swaggerOpIndex, httpMethod, pathTemplate string) *swaggerOperation {
	if idx == nil {
		return nil
	}
	methods := idx[strings.ToUpper(httpMethod)]
	if methods == nil {
		return nil
	}
	return methods[pathTemplate]
}

// swaggerRefPrefix 是 Swagger 2.0 definition 引用的标准前缀。
const swaggerRefPrefix = "#/definitions/"

// resolveSwaggerRef 解析 "#/definitions/<name>" 形式的 $ref，返回该 definition
// 的原始 schema。ref 非 definitions 引用、doc 为 nil 或 definition 不存在时返回 nil。
func resolveSwaggerRef(doc *swaggerDoc, ref string) json.RawMessage {
	if !strings.HasPrefix(ref, swaggerRefPrefix) {
		return nil
	}
	if doc == nil || doc.Definitions == nil {
		return nil
	}
	return doc.Definitions[ref[len(swaggerRefPrefix):]]
}

// refDefName 从 "#/definitions/<name>" 提取 <name>；非标准引用返回空串。
func refDefName(ref string) string {
	if !strings.HasPrefix(ref, swaggerRefPrefix) {
		return ""
	}
	return ref[len(swaggerRefPrefix):]
}

// inlineSwaggerSchema 将 schema（可能含 $ref）递归展开为自包含 map[string]any。
//
// 处理逻辑：
//  1. 含 $ref：
//     - 环检测：name 已在当前路径 seen 中 -> {"type":"object","description":"<name> (递归引用)"}
//     - 深度限制：depth > maxDepth -> {"type":"object"}（不再展开本 $ref）
//     - 否则 resolveSwaggerRef 后递归（depth+1）；seen 按路径回溯（进入加、返回删），
//     保证共享 definition（如 v1ErrorResponse 被引 98 次）不被误降级
//  2. inline schema：拷贝 type/format/enum/items/properties 等键，对 properties
//     与 items 递归；字段语义优先取 description，缺失时取 title 提升为 description
//     （swagger 产物约 99% 字段语义在 title，见 §11.2）
//
// 参数：
//   - schema: 原始 JSON（$ref 或 inline object/primitive）
//   - doc: 用于解析 $ref
//   - maxDepth: $ref 展开深度上限（建议 4；depth 超过此值则降级）
//   - depth: 当前已展开的 $ref 深度（从 0 起，含 body 参数自身的 $ref）
//   - seen: 当前展开路径上已遇到的 definition 名集合（环检测，须回溯；nil 则不检测）
func inlineSwaggerSchema(schema json.RawMessage, doc *swaggerDoc, maxDepth, depth int, seen map[string]struct{}) map[string]any {
	if len(schema) == 0 {
		return map[string]any{"type": "object"}
	}
	var m map[string]any
	if err := json.Unmarshal(schema, &m); err != nil {
		return map[string]any{"type": "object"}
	}
	return inlineSchemaObj(m, doc, maxDepth, depth, seen)
}

// inlineSchemaObj 处理已解析的 schema 对象，返回自包含 map。
// 是 inlineSwaggerSchema 的递归核心；seen 按路径回溯以保证共享 definition 不被误降级。
func inlineSchemaObj(m map[string]any, doc *swaggerDoc, maxDepth, depth int, seen map[string]struct{}) map[string]any {
	// $ref 分支
	if ref, ok := m["$ref"].(string); ok && ref != "" {
		name := refDefName(ref)
		if name != "" && seen != nil {
			if _, cyclic := seen[name]; cyclic {
				return map[string]any{"type": "object", "description": name + " (递归引用)"}
			}
		}
		if depth > maxDepth {
			return map[string]any{"type": "object"}
		}
		resolved := resolveSwaggerRef(doc, ref)
		if len(resolved) == 0 {
			return map[string]any{"type": "object"}
		}
		var rm map[string]any
		if err := json.Unmarshal(resolved, &rm); err != nil {
			return map[string]any{"type": "object"}
		}
		if name != "" && seen != nil {
			seen[name] = struct{}{}
		}
		out := inlineSchemaObj(rm, doc, maxDepth, depth+1, seen)
		if name != "" && seen != nil {
			delete(seen, name)
		}
		return out
	}

	// inline schema：拷贝键并递归 properties / items
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		switch k {
		case "properties":
			if props, ok := v.(map[string]any); ok {
				np := make(map[string]any, len(props))
				for pn, pv := range props {
					if psm, ok := pv.(map[string]any); ok {
						np[pn] = inlineSchemaObj(psm, doc, maxDepth, depth, seen)
					} else {
						np[pn] = pv
					}
				}
				out[k] = np
				continue
			}
		case "items":
			if im, ok := v.(map[string]any); ok {
				out[k] = inlineSchemaObj(im, doc, maxDepth, depth, seen)
				continue
			}
			if arr, ok := v.([]any); ok {
				na := make([]any, len(arr))
				for i, e := range arr {
					if em, ok := e.(map[string]any); ok {
						na[i] = inlineSchemaObj(em, doc, maxDepth, depth, seen)
					} else {
						na[i] = e
					}
				}
				out[k] = na
				continue
			}
		}
		out[k] = v
	}

	// 字段语义：title -> description 提升（description 缺失时）
	if t, ok := out["title"].(string); ok && t != "" {
		if _, has := out["description"]; !has {
			out["description"] = t
		}
	}
	return out
}

// primitiveParamSchema 为 path/query 基本类型参数构建子 schema。
//
// type 缺省视为 "string"；integer/number 保留 format；附带 description。
// 数组（type:array）参数输出 {"type":"array","items":{...}}，items 原样内联
// （query 数组元素恒为基本类型，不含 $ref）。
func primitiveParamSchema(p swaggerParameter) map[string]any {
	if p.Type == "array" {
		arr := map[string]any{"type": "array"}
		if len(p.Items) > 0 {
			var items map[string]any
			if err := json.Unmarshal(p.Items, &items); err == nil {
				arr["items"] = items
			}
		}
		if p.Description != "" {
			arr["description"] = p.Description
		}
		return arr
	}

	out := map[string]any{}
	t := p.Type
	if t == "" {
		t = "string"
	}
	out["type"] = t
	if p.Format != "" {
		out["format"] = p.Format
	}
	if p.Description != "" {
		out["description"] = p.Description
	}
	return out
}

// swaggerInlineMaxDepth 是 body schema $ref 展开的最大深度。
// 实测 CLI 微服务请求消息最大嵌套深度为 4，该值对 input schema 足够（0 截断）
// 且避免 token 浪费（见 §5.3）。
const swaggerInlineMaxDepth = 4

// buildInputSchemaFromSwagger 基于 swagger operation + gateway body 配置构建 input JSON Schema。
//
// 处理逻辑：
//  1. op == nil -> 降级为 buildInputSchema(pathTemplate)（仅 path 参数，即当前行为）。
//  2. 遍历 op.Parameters 按 in 分类：
//     - "path":  properties[name]=primitiveParamSchema(p)，加入 required（path 参数恒必填）
//     - "query": properties[name]=primitiveParamSchema(p)（含数组），p.Required 时加入 required
//     - "body":  inline 展开 p.Schema 后由 flattenBodySchema 处理：
//     - object 含 properties -> 各 property 合并进顶层 properties（展平），其 required 合并进顶层
//     （body:"*" / body:"fieldname" 消息字段类型）
//     - 基本类型/array -> properties[bodyField]=展开结果（body:"fieldname" 标量字段）
//     - object 无 properties（空请求消息）-> 不新增字段（见 §5.4）
//
// 返回 {"type":"object","properties":{...},"required":[...]}（required 为空时省略）。
//
// 展平 body 字段使 LLM 以扁平 JSON 提供参数，与 handler 发送给 gateway 的 flat body 一致；
// body:"fieldname" 时由 handler（Step 4）再包装为 {"fieldname":<flat>}。
func buildInputSchemaFromSwagger(op *swaggerOperation, bodyField, pathTemplate string, doc *swaggerDoc) map[string]any {
	if op == nil {
		return buildInputSchema(pathTemplate)
	}

	props := make(map[string]any)
	required := make([]string, 0)
	requiredSet := make(map[string]struct{})
	addRequired := func(name string) {
		if name == "" {
			return
		}
		if _, ok := requiredSet[name]; !ok {
			requiredSet[name] = struct{}{}
			required = append(required, name)
		}
	}

	for i := range op.Parameters {
		p := op.Parameters[i]
		switch p.In {
		case "path":
			props[p.Name] = primitiveParamSchema(p)
			addRequired(p.Name)
		case "query":
			props[p.Name] = primitiveParamSchema(p)
			if p.Required {
				addRequired(p.Name)
			}
		case "body":
			fields, reqs := flattenBodySchema(p, bodyField, doc)
			for name, sub := range fields {
				props[name] = sub
			}
			for _, r := range reqs {
				addRequired(r)
			}
		}
	}

	schema := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

// flattenBodySchema 展开 body 参数 schema，返回需合并进顶层 input schema 的字段。
//
// 返回：
//   - fields: 字段名 -> 子 schema
//   - object 含 properties：展平后的 body 字段（body:"*" / body:"fieldname" 消息字段）
//   - 基本类型/array：{bodyField: 展开结果}（body:"fieldname" 标量字段；bodyField 空时兜底为参数名）
//   - required: body definition 顶层 required 数组中的字段名（展平后即为顶层必填字段）
func flattenBodySchema(p swaggerParameter, bodyField string, doc *swaggerDoc) (fields map[string]any, required []string) {
	expanded := inlineSwaggerSchema(p.Schema, doc, swaggerInlineMaxDepth, 0, map[string]struct{}{})

	// 展开结果为 object 且含 properties -> 展平
	if expanded["type"] == "object" {
		if props, ok := expanded["properties"].(map[string]any); ok && len(props) > 0 {
			fields = props
			if reqArr, ok := expanded["required"].([]any); ok {
				for _, r := range reqArr {
					if s, ok := r.(string); ok {
						required = append(required, s)
					}
				}
			}
			return fields, required
		}
		// object 但无 properties（空请求消息）：不新增字段
		return nil, nil
	}

	// 基本类型 / array（body:"fieldname" 标量字段）：以 bodyField 为键
	name := bodyField
	if name == "" {
		name = p.Name // 兜底（通常为 "body"）
	}
	if name == "" {
		return nil, nil
	}
	return map[string]any{name: expanded}, nil
}

// pathParamNames 从 path 模板提取 {param} 名称集合。
func pathParamNames(pathTemplate string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, m := range pathParamRegex.FindAllStringSubmatch(pathTemplate, -1) {
		out[m[1]] = struct{}{}
	}
	return out
}

// queryParamNames 从 swagger 操作提取 in=="query" 的参数名集合。op 为 nil 时返回 nil。
func queryParamNames(op *swaggerOperation) map[string]struct{} {
	if op == nil {
		return nil
	}
	out := make(map[string]struct{})
	for _, p := range op.Parameters {
		if p.In == "query" {
			out[p.Name] = struct{}{}
		}
	}
	return out
}

// bodyParamSchemaKind 判断 body 参数 schema 是 object（消息字段）还是 scalar（基本类型/array）。
// 返回 "object"、"scalar" 或 ""（无 body 参数）。$ref 与 type:object/缺省均视为 object。
func bodyParamSchemaKind(op *swaggerOperation) string {
	if op == nil {
		return ""
	}
	for _, p := range op.Parameters {
		if p.In != "body" {
			continue
		}
		if len(p.Schema) == 0 {
			return "object"
		}
		var m map[string]any
		if json.Unmarshal(p.Schema, &m) != nil {
			return "object"
		}
		if _, hasRef := m["$ref"]; hasRef {
			return "object"
		}
		if t, _ := m["type"].(string); t == "" || t == "object" {
			return "object"
		}
		return "scalar"
	}
	return ""
}

// buildRequestBody 根据 swagger 参数分类 + gateway bodyField 构建请求体。
//
// body 格式（经生成 gateway 代码实证：body 直接 Decode 进 protoReq 或 protoReq.<字段>，
// 故 body 为字段值本身，不包装）：
//   - bodyField == ""：无 body 映射，返回 (nil, false)（参数走 query）
//   - bodyField == "*" 或 "fieldname"（消息字段）：body = 非 path/非 query 参数的 flat 对象；
//     无参数时为 "{}"
//   - bodyField == "fieldname"（标量字段）：body = args[bodyField] 的原始 JSON 值；未提供则 (nil, false)
//
// 参数是否属于 query：以 op.Parameters 中 in=="query" 的 name 集合为准（命名即 grpc-gateway 期望）。
// op 为 nil 时退化为「非 path 即 body」。
//
// 注意：本文档 §4.2.7 原述 body:"fieldname" 包装为 {"fieldname":<flat>} 有误（与 gateway 的
// Decode(&protoReq.<field>) 语义冲突），已据 admin.pb.gw.go 实证修正为不包装（见 §4.2.7 修订）。
func buildRequestBody(args map[string]json.RawMessage, op *swaggerOperation, pathTemplate, bodyField string) (json.RawMessage, bool) {
	if bodyField == "" {
		return nil, false
	}

	pathSet := pathParamNames(pathTemplate)
	querySet := queryParamNames(op)

	bodyArgs := make(map[string]json.RawMessage)
	for k, v := range args {
		if _, isPath := pathSet[k]; isPath {
			continue
		}
		if querySet != nil {
			if _, isQuery := querySet[k]; isQuery {
				continue
			}
		}
		bodyArgs[k] = v
	}

	// 标量 body：发送字段原始值
	if bodyParamSchemaKind(op) == "scalar" {
		if v, ok := bodyArgs[bodyField]; ok {
			return v, true
		}
		return nil, false
	}

	// 消息 body（body:"*" 或 body:"fieldname" 消息字段）：flat 对象，不包装
	b, err := json.Marshal(bodyArgs)
	if err != nil {
		return nil, false
	}
	return b, true
}

// queryValues 将单个参数的 JSON 原始值转换为 query 值列表。
// 数组展开为多值（重复参数名）；null/空字符串跳过；对象/数字/布尔取 JSON 文本。
func queryValues(raw json.RawMessage) []string {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil
	}
	if raw[0] == '[' {
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) != nil {
			return nil
		}
		var out []string
		for _, e := range arr {
			out = append(out, queryValues(e)...)
		}
		return out
	}
	if bytes.Equal(raw, []byte("null")) {
		return nil
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return nil
		}
		if s == "" {
			return nil
		}
		return []string{s}
	}
	return []string{string(raw)}
}

// appendQueryParams 为请求 URL 追加 query string。
//
// 仅取 op 中 in=="query" 的参数（op 为 nil 时取所有非 path 参数）。命名直接使用 swagger
// 给定的 name（已为 grpc-gateway 期望格式，含点分嵌套名如 ping.name）。
// 值编码：字符串去引号；数字/布尔取 JSON 文本；数组重复参数名（?tag=a&tag=b）；
// 对象 marshal 为 JSON 文本作为单值；空字符串/null 跳过。
func appendQueryParams(base, pathTemplate string, op *swaggerOperation, args map[string]json.RawMessage) string {
	pathSet := pathParamNames(pathTemplate)
	querySet := queryParamNames(op)

	vals := url.Values{}
	for k, raw := range args {
		if _, isPath := pathSet[k]; isPath {
			continue
		}
		if querySet != nil {
			if _, isQuery := querySet[k]; !isQuery {
				continue
			}
		}
		for _, v := range queryValues(raw) {
			vals.Add(k, v)
		}
	}

	if len(vals) == 0 {
		return base
	}
	return base + "?" + vals.Encode()
}

// lookupOpDocs 解析 tool 的 summary/description/tags：swagger 优先，openapiv2 docMap 兜底。
// 返回原始三值，由调用方按既有逻辑 mergeSummaryDescription + formatDescription 组装最终描述。
func lookupOpDocs(op *swaggerOperation, docMap map[string]swaggerMethod, selector string) (summary, description string, tags []string) {
	if op != nil {
		summary = op.Summary
		description = op.Description
		tags = op.Tags
	}
	if docMap != nil {
		if entry, ok := docMap[selector]; ok {
			if summary == "" {
				summary = entry.summary
			}
			if description == "" {
				description = entry.description
			}
			if len(tags) == 0 {
				tags = entry.tags
			}
		}
	}
	return summary, description, tags
}
