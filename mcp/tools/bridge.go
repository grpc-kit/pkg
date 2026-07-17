package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/grpc-kit/pkg/admin/openapiconfig"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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
) error {
	_ = connFn // 暂未使用，预留 gRPC reflection 优化
	if server == nil {
		return nil
	}
	if gatewayCfg == nil {
		return nil
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	// 构建 selector -> swagger Operation 映射表
	docMap := buildSelectorDocMap(swaggerCfg)

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

		baseName := toSnakeCase(serviceName) + "_" + toSnakeCase(methodName)
		summary, description, tags := lookupSwaggerDoc(docMap, rule.GetSelector())

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
			inputSchema := buildInputSchema(pathTemplate)
			desc := formatDescription(tags, mergeSummaryDescription(summary, description))

			// 捕获循环变量
			method := httpMethod
			tmpl := pathTemplate
			handler := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return bridgeHandler(ctx, req, httpClient, httpBaseURL, method, tmpl)
			}

			server.AddTool(&mcp.Tool{
				Name:        toolName,
				Description: desc,
				InputSchema: inputSchema,
			}, handler)
		}
	}

	return nil
}

// bridgeHandler 实际执行 HTTP 调用的 handler。
func bridgeHandler(
	ctx context.Context,
	req *mcp.CallToolRequest,
	httpClient *http.Client,
	httpBaseURL, httpMethod, pathTemplate string,
) (*mcp.CallToolResult, error) {
	args := parseArguments(req.Params.Arguments)

	// 替换 path 参数
	path, missing := substitutePathParams(pathTemplate, args)
	if missing != "" {
		return errorResult("missing path parameter: " + missing), nil
	}

	// 构建完整 URL
	base := strings.TrimRight(httpBaseURL, "/")
	url := base + path

	var (
		bodyReader io.Reader
		contentSet bool
	)
	if !isIdempotentMethod(httpMethod) {
		// 非幂等方法：body 整体为 JSON
		raw, ok := extractBodyArgs(args, path)
		if !ok {
			raw = json.RawMessage("{}")
		}
		bodyReader = bytes.NewReader(raw)
		contentSet = true
	}

	httpReq, err := http.NewRequestWithContext(ctx, httpMethod, url, bodyReader)
	if err != nil {
		return errorResult("build request: " + err.Error()), nil
	}
	if contentSet {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return errorResult("http call: " + err.Error()), nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return errorResult("read response: " + err.Error()), nil
	}

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

// lookupSwaggerDoc 从映射表查找文档。selector 在映射中不存在时返回空字段。
func lookupSwaggerDoc(docMap map[string]swaggerMethod, selector string) (summary, description string, tags []string) {
	entry, ok := docMap[selector]
	if !ok {
		return "", "", nil
	}
	return entry.summary, entry.description, entry.tags
}

// mergeSummaryDescription 合并 summary 与 description：summary 优先。
func mergeSummaryDescription(summary, description string) string {
	if summary != "" {
		return summary
	}
	return description
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

// extractBodyArgs 提取 body 参数（去除已用于 path 的参数）。
//
// 幂等方法（GET/DELETE 等）返回 (nil, false) 表示不需要 body。
// 非幂等方法返回剩余参数（任意 JSON）。
func extractBodyArgs(args map[string]json.RawMessage, path string) (json.RawMessage, bool) {
	// 收集 path 参数名
	pathParams := make(map[string]struct{})
	for _, m := range pathParamRegex.FindAllStringSubmatch(path, -1) {
		pathParams[m[1]] = struct{}{}
	}

	// 构造剩余对象
	filtered := make(map[string]json.RawMessage, len(args))
	for k, v := range args {
		if _, isPath := pathParams[k]; isPath {
			continue
		}
		filtered[k] = v
	}

	if len(filtered) == 0 {
		return nil, false
	}

	b, err := json.Marshal(filtered)
	if err != nil {
		return nil, false
	}
	return b, true
}
