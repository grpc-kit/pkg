// 静态字典派生（Phase 1 / P2）
//
// 从业务方提供的 `*.gateway.yaml` + `*.openapiv2.yaml`（通常存放在
// `openapi/microservice.gateway.yaml` 与 `openapi/microservice.openapiv2.yaml`，
// 以及 `pkg/api/known/admin/v1/openapi/admin.{gateway,openapiv2}.yaml`）
// 派生出权限决策所需的 **services / rpc_routes / gateway_routes** 三张表。
//
// 设计要点：
//
//   - 与 `pkg/admin/rpc_services.go` 中的派生逻辑**功能等价**，但**独立实现**，
//     避免 `pkg/auth` 反向依赖 `pkg/admin`。
//   - **P2 阶段仅提供构造与输出能力，不接入 `OPARegoConfig`**；
//     由 P3 阶段在 `initOPARego` 中把 `BuildOPAData()` 合并注入 OPA data 树。
//   - 内部使用本包私有结构体（`Service` / `Action` / `ResourceSelector` /
//     `GatewayRoute`），不耦合 `pkg/api/known/admin/v1` 类型，便于后续期独立演进。
//
// 详见 [adm/docs/roadmap/permission-opa-policy-loader.md] §3.2 与 §6.2-P2。

package auth

import (
	"bytes"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	"github.com/grpc-kit/pkg/admin/openapiconfig"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/genproto/googleapis/api/serviceconfig"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"
)

// StaticDict 静态字典：从 *.gateway.yaml + *.openapiv2.yaml 派生而来的服务/动作/路由反查表。
//
// 字段在派生完成后视为只读；并发场景下整体由调用方在合并到 OPA data 时统一加锁。
type StaticDict struct {
	// Services 按 svc_code（如 "known.admin.api"）索引的服务定义，
	// 同一 service 内的 Actions 按 grpc method 名索引。
	Services map[string]*Service

	// RPCRoutes gRPC 全限定路径反查表：`/<grpc_service>/<method>` → action_id。
	// 例如：`/grpc_kit.api.known.admin.v1.KnownAdmin/CreateAuthLogin`
	//      → `known.admin.api:CreateAuthLogin`
	RPCRoutes map[string]string

	// GatewayRoutes grpc-gateway HTTP 路由表：保留 method + path template + action_id，
	// 供 HTTP 入口侧将 `(METHOD, /api/...)` 反查回 action_id。
	GatewayRoutes []GatewayRoute
}

// Service 一组动作的归属服务。
type Service struct {
	// Code 服务编码，如 "known.admin.api"，由 selector 的第 3/4/2 段拼接得到。
	Code string
	// GrpcService gRPC 全限定服务名，如 "grpc_kit.api.known.admin.v1.KnownAdmin"。
	GrpcService string
	// DisplayName 服务展示名（取 *.gateway.yaml 的 `title` 字段）。
	DisplayName string
	// Actions 按 grpc method 名索引的动作集合。
	Actions map[string]*Action
}

// Action 一个 gRPC method 对应的可鉴权动作。
type Action struct {
	// Code 形如 "known.admin.api:CreateAuthLogin"。
	Code string
	// GrpcMethod 仅 method 名，如 "CreateAuthLogin"。
	GrpcMethod string
	// DisplayName 取自 OpenAPI Operation summary。
	DisplayName string
	// Description 取自 OpenAPI Operation description。
	Description string
	// Tags 取自 OpenAPI Operation tags。
	Tags []string
	// ResourceSelectors 由 HTTP path 模板中的 `{var=pattern}` 推导出的资源选择器。
	ResourceSelectors []ResourceSelector
}

// ResourceSelector 资源选择器（auth 包内独立类型，与
// `pkg/api/known/admin/v1.Action_ResourceSelector` 同构，但**不互相依赖**）。
type ResourceSelector struct {
	ResourceType string
	// Pattern 形如 `grn:${partition}:<svc_code>:${region_code}:${account_id}:<rt>/<pat>`。
	// `${partition}` / `${region_code}` / `${account_id}` 占位符由后续期（P12）的
	// input_builder 在请求评估时根据 `Config.Partition` 等注入。
	Pattern string
}

// GatewayRoute HTTP 入口路由项：保留 `(method, path_template, action_id)` 三元组。
type GatewayRoute struct {
	Method       string // GET / POST / PUT / DELETE / PATCH / CUSTOM 等
	PathTemplate string // 形如 "/builtin/admin/api/v1/auth/login"
	ActionID     string // 形如 "known.admin.api:CreateAuthLogin"
}

// staticDictAssetNames 默认在每份 `fs.FS` 中查找的两份文件路径前缀。
// 与 [pkg/admin/gateway_service_config.go] `setMicroserviceGatewayYAML` 保持一致：
//   - openapi/microservice.gateway.yaml + openapi/microservice.openapiv2.yaml
//   - openapi/admin.gateway.yaml        + openapi/admin.openapiv2.yaml
var staticDictAssetNames = []struct {
	GatewayYAML string
	SwaggerYAML string
}{
	{GatewayYAML: "openapi/microservice.gateway.yaml", SwaggerYAML: "openapi/microservice.openapiv2.yaml"},
	{GatewayYAML: "openapi/admin.gateway.yaml", SwaggerYAML: "openapi/admin.openapiv2.yaml"},
}

// httpPathVarRegexp 匹配 HTTP path 模板中的 `{var}` 或 `{var=pattern}` 段。
var httpPathVarRegexp = regexp.MustCompile(`{([^{}]+)}`)

// NewStaticDict 在多个资源 FS 上派生静态字典。
//
// 调用约定：
//   - 至少一份 `fs.FS` 中需要包含可解析的 gateway/swagger 配对；全部缺失则返回 error，
//     由调用方决定 fail-fast 还是降级（P3 之前 P2 调用方仅为单测）。
//   - 解析单个文件出错（YAML 损坏等）即返回 error，不做静默吞错——便于 CI 早期发现。
//   - 同一 svc_code 出现在多份 assets 中时，按出现顺序合并 Actions；同名 method 后者覆盖前者。
func NewStaticDict(assetFSs ...fs.FS) (*StaticDict, error) {
	sd := &StaticDict{
		Services:      map[string]*Service{},
		RPCRoutes:     map[string]string{},
		GatewayRoutes: []GatewayRoute{},
	}

	matched := 0
	for _, assets := range assetFSs {
		if assets == nil {
			continue
		}
		for _, pair := range staticDictAssetNames {
			gwData, ok, err := readAssetFile(assets, pair.GatewayYAML)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
			swData, _, err := readAssetFile(assets, pair.SwaggerYAML)
			if err != nil {
				return nil, err
			}
			matched++

			svcConfig, err := parseGatewayYAML(gwData)
			if err != nil {
				return nil, fmt.Errorf("static dict: parse %s: %w", pair.GatewayYAML, err)
			}
			if svcConfig == nil {
				continue
			}
			swaggerCfg, err := parseSwaggerYAML(swData)
			if err != nil {
				return nil, fmt.Errorf("static dict: parse %s: %w", pair.SwaggerYAML, err)
			}
			ops := indexOpenAPIOperations(swaggerCfg)

			if err := sd.absorbServiceConfig(svcConfig, ops); err != nil {
				return nil, err
			}
		}
	}

	if matched == 0 {
		return nil, fmt.Errorf("static dict: no gateway yaml found in %d asset(s)", len(assetFSs))
	}
	return sd, nil
}

// BuildOPAData 把静态字典输出为可注入 OPA data 树的 map（与 §3.2 L1 框架自动派生层对齐）。
//
// 输出形如：
//
//	{
//	  "services":       { "<svc_code>": { ... } },
//	  "rpc_routes":     { "/<grpc_svc>/<method>": "<action_id>" },
//	  "gateway_routes": [ {"method", "path_template", "action_id"}, ... ]
//	}
//
// 注意：直接返回内部 map/slice 的引用；调用方（P3 阶段的 `initOPARego`）负责在写入
// OPA data 前合并/拷贝，避免与并发 Reload 互相影响。
func (sd *StaticDict) BuildOPAData() map[string]any {
	if sd == nil {
		return map[string]any{
			"services":       map[string]*Service{},
			"rpc_routes":     map[string]string{},
			"gateway_routes": []GatewayRoute{},
		}
	}
	return map[string]any{
		"services":       sd.Services,
		"rpc_routes":     sd.RPCRoutes,
		"gateway_routes": sd.GatewayRoutes,
	}
}

// absorbServiceConfig 把一份解析好的 *.gateway.yaml 合并进字典。
func (sd *StaticDict) absorbServiceConfig(svcConfig *serviceconfig.Service, ops map[string]*options.Operation) error {
	if svcConfig == nil || svcConfig.Http == nil {
		return nil
	}

	for _, rule := range svcConfig.Http.GetRules() {
		selector := rule.GetSelector()
		parts := strings.Split(selector, ".")
		if len(parts) < 7 {
			// 段数不足无法派生 svc_code，跳过该 rule；交由 CI 一致性检查（Phase 3）兜底。
			continue
		}
		svcCode := fmt.Sprintf("%v.%v.%v", parts[3], parts[4], parts[2])
		grpcSvc := strings.Join(parts[:6], ".")
		grpcMethod := parts[6]
		actCode := fmt.Sprintf("%v:%v", svcCode, grpcMethod)

		svc := sd.upsertService(svcCode, grpcSvc, svcConfig.GetTitle())
		act := &Action{
			Code:       actCode,
			GrpcMethod: grpcMethod,
		}
		if op, ok := ops[selector]; ok && op != nil {
			act.DisplayName = op.GetSummary()
			act.Description = op.GetDescription()
			act.Tags = op.GetTags()
		}
		act.ResourceSelectors = appendPathVariableSelectors(svcCode, act.ResourceSelectors, httpRulePathTemplates(rule))
		svc.Actions[grpcMethod] = act

		sd.RPCRoutes[fmt.Sprintf("/%v/%v", grpcSvc, grpcMethod)] = actCode
		for _, t := range httpRulePathTemplates(rule) {
			sd.GatewayRoutes = append(sd.GatewayRoutes, GatewayRoute{
				Method:       httpVerb(rule),
				PathTemplate: t,
				ActionID:     actCode,
			})
		}
	}
	return nil
}

// upsertService 取出或新建一个 svc_code 对应的 Service；DisplayName 仅在为空时才写入。
func (sd *StaticDict) upsertService(svcCode, grpcSvc, displayName string) *Service {
	svc, ok := sd.Services[svcCode]
	if !ok {
		svc = &Service{
			Code:        svcCode,
			GrpcService: grpcSvc,
			DisplayName: displayName,
			Actions:     map[string]*Action{},
		}
		sd.Services[svcCode] = svc
		return svc
	}
	if svc.DisplayName == "" {
		svc.DisplayName = displayName
	}
	if svc.GrpcService == "" {
		svc.GrpcService = grpcSvc
	}
	return svc
}

// --- 文件解析辅助 ---

// readAssetFile 从一个 fs.FS 中读取指定路径；文件不存在时返回 ok=false 而非 error。
func readAssetFile(assets fs.FS, name string) (data []byte, ok bool, err error) {
	f, err := assets.Open(name)
	if err != nil {
		if isFSNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("static dict: open %s: %w", name, err)
	}
	defer f.Close()

	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(f); err != nil {
		return nil, false, fmt.Errorf("static dict: read %s: %w", name, err)
	}
	return buf.Bytes(), true, nil
}

func isFSNotExist(err error) bool {
	if err == nil {
		return false
	}
	pe, ok := err.(*fs.PathError)
	if !ok {
		return false
	}
	return pe.Err != nil && (pe.Err.Error() == "file does not exist" || strings.Contains(pe.Err.Error(), "no such file"))
}

// parseGatewayYAML 等价于 pkg/admin 中的 parseMicroserviceGatewayYAML。
func parseGatewayYAML(data []byte) (*serviceconfig.Service, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	jsonBody, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("yaml→json: %w", err)
	}
	out := &serviceconfig.Service{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(jsonBody, out); err != nil {
		return nil, fmt.Errorf("unmarshal service config: %w", err)
	}
	return out, nil
}

// parseSwaggerYAML 等价于 pkg/admin 中的 parseMicroserviceSwaggerYAML。
// 与 admin 版本的细微差异：本函数允许 swagger 为空（返回 nil, nil）——P2 阶段还没有要求每个
// gateway.yaml 都必须配一份 swagger，缺失时仅意味着 Action 缺 DisplayName/Description。
func parseSwaggerYAML(data []byte) (*openapiconfig.OpenAPIConfig, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	jsonBody, err := yaml.YAMLToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("yaml→json: %w", err)
	}
	out := &openapiconfig.OpenAPIConfig{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(jsonBody, out); err != nil {
		return nil, fmt.Errorf("unmarshal openapi config: %w", err)
	}
	return out, nil
}

// indexOpenAPIOperations 建立 selector → *options.Operation 的索引。
func indexOpenAPIOperations(cfg *openapiconfig.OpenAPIConfig) map[string]*options.Operation {
	out := map[string]*options.Operation{}
	if cfg == nil || cfg.OpenapiOptions == nil {
		return out
	}
	for _, item := range cfg.OpenapiOptions.GetMethod() {
		if item == nil {
			continue
		}
		out[item.GetMethod()] = item.GetOption()
	}
	return out
}

// --- HTTP rule / 路径变量推导（与 pkg/admin/rpc_services.go 同构） ---

// httpRulePathTemplates 返回 rule + additional_bindings 的全部 path 模板。
func httpRulePathTemplates(rule *annotations.HttpRule) []string {
	if rule == nil {
		return nil
	}
	templates := make([]string, 0, 1+len(rule.GetAdditionalBindings()))
	if t := httpRulePrimaryPathTemplate(rule); t != "" {
		templates = append(templates, t)
	}
	for _, binding := range rule.GetAdditionalBindings() {
		templates = append(templates, httpRulePathTemplates(binding)...)
	}
	return templates
}

func httpRulePrimaryPathTemplate(rule *annotations.HttpRule) string {
	if rule == nil {
		return ""
	}
	switch {
	case rule.GetGet() != "":
		return rule.GetGet()
	case rule.GetPut() != "":
		return rule.GetPut()
	case rule.GetPost() != "":
		return rule.GetPost()
	case rule.GetDelete() != "":
		return rule.GetDelete()
	case rule.GetPatch() != "":
		return rule.GetPatch()
	default:
		if custom := rule.GetCustom(); custom != nil {
			return custom.GetPath()
		}
	}
	return ""
}

// httpVerb 返回 rule 的 HTTP method（统一大写）。Custom rule 取其 `kind`。
func httpVerb(rule *annotations.HttpRule) string {
	if rule == nil {
		return ""
	}
	switch {
	case rule.GetGet() != "":
		return "GET"
	case rule.GetPut() != "":
		return "PUT"
	case rule.GetPost() != "":
		return "POST"
	case rule.GetDelete() != "":
		return "DELETE"
	case rule.GetPatch() != "":
		return "PATCH"
	default:
		if custom := rule.GetCustom(); custom != nil {
			return strings.ToUpper(custom.GetKind())
		}
	}
	return ""
}

// appendPathVariableSelectors 与 pkg/admin/rpc_services.go 中的同名函数功能等价；
// 不同之处：输出本包私有的 `ResourceSelector` 而非 adminv1 类型，避免反向依赖。
func appendPathVariableSelectors(serviceCode string, in []ResourceSelector, templates []string) []ResourceSelector {
	if len(templates) == 0 {
		return in
	}
	result := in
	seen := make(map[string]struct{}, len(in))
	for _, sel := range in {
		seen[sel.ResourceType+"\n"+sel.Pattern] = struct{}{}
	}
	for _, template := range templates {
		for _, variable := range extractHTTPPathVariables(template) {
			pattern := fmt.Sprintf("grn:${partition}:%v:${region_code}:${account_id}:%v/%v",
				serviceCode, variable.resourceType, variable.pattern)
			key := variable.resourceType + "\n" + pattern
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, ResourceSelector{
				ResourceType: variable.resourceType,
				Pattern:      pattern,
			})
		}
	}
	return result
}

type pathVariable struct {
	resourceType string
	pattern      string
}

// extractHTTPPathVariables 解析 `{var}` / `{var=pattern}` 段。
func extractHTTPPathVariables(template string) []pathVariable {
	if template == "" {
		return nil
	}
	matches := httpPathVarRegexp.FindAllStringSubmatch(template, -1)
	if len(matches) == 0 {
		return nil
	}
	result := make([]pathVariable, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		token := strings.TrimSpace(match[1])
		if token == "" {
			continue
		}
		resourceType := token
		pattern := "*"
		if i := strings.Index(token, "="); i >= 0 {
			resourceType = strings.TrimSpace(token[:i])
			pattern = strings.TrimSpace(token[i+1:])
			if pattern == "" {
				pattern = "*"
			}
		}
		if resourceType == "" {
			continue
		}
		result = append(result, pathVariable{resourceType: resourceType, pattern: pattern})
	}
	return result
}

// SortedGatewayRoutes 返回按 (PathTemplate, Method) 稳定排序后的副本，便于测试与诊断输出。
// 主体 GatewayRoutes 字段刻意保留派生顺序（与 .gateway.yaml 的 rules 顺序一致），便于人工对照。
func (sd *StaticDict) SortedGatewayRoutes() []GatewayRoute {
	if sd == nil {
		return nil
	}
	out := append([]GatewayRoute(nil), sd.GatewayRoutes...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PathTemplate != out[j].PathTemplate {
			return out[i].PathTemplate < out[j].PathTemplate
		}
		return out[i].Method < out[j].Method
	})
	return out
}
