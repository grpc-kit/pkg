package admin

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	"github.com/grpc-kit/pkg/admin/openapiconfig"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/genproto/googleapis/api/serviceconfig"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var httpPathVarRegexp = regexp.MustCompile(`{([^{}]+)}`)

func lionServiceToProto(in *lion.Services) *adminv1.Service {
	if in == nil {
		return nil
	}
	return &adminv1.Service{
		Id:          int64(in.ID),
		Code:        in.Code,
		GrpcService: in.GrpcName,
		DisplayName: in.DisplayName,
		Description: in.Description,
		Protected:   in.Protected,
		CreatedBy:   in.CreatedBy,
		UpdatedBy:   in.UpdatedBy,
		CreatedAt:   timestamppb.New(in.CreatedAt),
		UpdatedAt:   timestamppb.New(in.UpdatedAt),
	}
}

func (a *KnownAdminAPI) ListServices(ctx context.Context, req *adminv1.ListServicesRequest) (*adminv1.ListServicesResponse, error) {
	result := &adminv1.ListServicesResponse{
		Services: make([]*adminv1.Service, 0),
	}

	// DEBUG, begin
	xxx, err := a.getKnownAdminGatewayServiceConfig()
	if err != nil {
		return nil, err
	}

	grpcName1 := xxx.Http.GetRules()[0].Selector
	temp1 := strings.Split(grpcName1, ".")
	codeName1 := fmt.Sprintf("%v.%v.%v", temp1[3], temp1[4], temp1[2])

	result.Services = append(result.Services,
		&adminv1.Service{Id: 1, Code: codeName1, GrpcService: strings.Join(temp1[:6], "."), DisplayName: xxx.Title, Protected: true},
	)

	yyy, err := a.getMicroserviceGatewayServiceConfig()
	if err != nil {
		return nil, err
	}

	grpcName2 := yyy.Http.GetRules()[0].Selector
	temp2 := strings.Split(grpcName2, ".")
	codeName2 := fmt.Sprintf("%v.%v.%v", temp2[3], temp2[4], temp2[2])

	result.Services = append(result.Services,
		&adminv1.Service{Id: 2, Code: codeName2, GrpcService: strings.Join(temp2[:6], "."), DisplayName: yyy.Title, Protected: true},
	)
	// DEBUG, end

	result.TotalSize = 2

	/*
		knownSwagger, err := a.getKnownAdminGatewaySwagger()
		if err != nil {
			return nil, err
		}

		for k, v := range knownSwagger.OpenapiOptions.Method {
			fmt.Println("k:", k, "v:", v)
		}
	*/

	return result, nil
}

func (a *KnownAdminAPI) ListServiceActions(ctx context.Context, req *adminv1.ListServiceActionsRequest) (*adminv1.ListServiceActionsResponse, error) {
	result := &adminv1.ListServiceActionsResponse{
		Actions: make([]*adminv1.Action, 0),
	}

	var err error
	var swaggers *openapiconfig.OpenAPIConfig
	var yyy *serviceconfig.Service

	// DEBUG, begin
	docsmap := make(map[string]*options.Operation, 0)

	if req.Parent == "admin.v1.known" {
		swaggers, err = a.getKnownAdminGatewaySwagger()
		if err != nil {
			return nil, err
		}
		yyy, err = a.getKnownAdminGatewayServiceConfig()
		if err != nil {
			return nil, err
		}
	} else {
		swaggers, err = a.getMicroserviceGatewaySwagger()
		if err != nil {
			return nil, err
		}
		yyy, err = a.getMicroserviceGatewayServiceConfig()
		if err != nil {
			return nil, err
		}
	}

	for _, v := range swaggers.OpenapiOptions.Method {
		docsmap[v.Method] = v.Option
	}

	for k, v := range yyy.Http.GetRules() {
		idx := k + 1

		temp2 := strings.Split(v.Selector, ".")
		serviceCode := fmt.Sprintf("%v.%v.%v", temp2[3], temp2[4], temp2[2])
		grpcMethod := temp2[6]

		act := &adminv1.Action{Id: int64(idx),
			Code:              fmt.Sprintf("%v:%v", serviceCode, grpcMethod),
			GrpcMethod:        grpcMethod,
			Protected:         true,
			ResourceSelectors: make([]*adminv1.Action_ResourceSelector, 0)}

		opt, ok := docsmap[v.Selector]
		if ok {
			act.DisplayName = opt.GetSummary()
			act.Description = opt.GetDescription()
		}

		// 如果 v 中的 url 定义存在变量，则把它添加到 resource_selectors 中，比如：
		/*
			  - selector: default.api.oneops.netdev.v1.OneopsNetdev.DeleteSwitchAdminUser
				    delete: "/api/switch/admin/user/{username}"

				  - selector: default.api.oneops.netdev.v1.OneopsNetdev.ListSwitchAdminUsers
				    get: "/api/switch/admin/users"

				  - selector: default.api.oneops.netdev.v1.OneopsNetdev.DeleteSSHBastionHost
				    delete: "/api/ssh/bastion/host/{host}"
		*/
		act.ResourceSelectors = appendPathVariableSelectors(serviceCode, act.ResourceSelectors, httpRulePathTemplates(v))

		result.Actions = append(result.Actions, act)
	}

	// DEBUG, end

	result.TotalSize = int32(len(yyy.Http.GetRules()))

	/*
		knownSwagger, err := a.getKnownAdminGatewaySwagger()
		if err != nil {
			return nil, err
		}

		for k, v := range knownSwagger.OpenapiOptions.Method {
			fmt.Println("k:", k, "v:", v)
		}
	*/

	return result, nil
}

func httpRulePathTemplates(rule *annotations.HttpRule) []string {
	if rule == nil {
		return nil
	}

	templates := make([]string, 0, 1+len(rule.GetAdditionalBindings()))
	if template := httpRulePrimaryPathTemplate(rule); template != "" {
		templates = append(templates, template)
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

func appendPathVariableSelectors(serviceCode string, in []*adminv1.Action_ResourceSelector, templates []string) []*adminv1.Action_ResourceSelector {
	// pattern 格式为：grn:${service_code}:${region_code}:${account_id}:${resource_type}/${resource_path}

	if len(templates) == 0 {
		return in
	}

	result := in
	seen := make(map[string]struct{}, len(in))
	for _, selector := range in {
		if selector == nil {
			continue
		}
		seen[selector.GetResourceType()+"\n"+selector.GetPattern()] = struct{}{}
	}

	for _, template := range templates {
		for _, variable := range extractHTTPPathVariables(template) {
			key := variable.resourceType + "\n" + variable.pattern
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, &adminv1.Action_ResourceSelector{
				ResourceType: variable.resourceType,
				Pattern:      fmt.Sprintf("grn:%v:${region_code}:${account_id}:%v/%v", serviceCode, variable.resourceType, variable.pattern),
			})
		}
	}

	return result
}

type pathVariable struct {
	resourceType string
	pattern      string
}

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
