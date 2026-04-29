package admin

import (
	"context"
	"fmt"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/options"
	"github.com/grpc-kit/pkg/admin/openapiconfig"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion"
	"google.golang.org/genproto/googleapis/api/serviceconfig"
	"google.golang.org/protobuf/types/known/timestamppb"
)

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

		act := &adminv1.Action{Id: int64(idx), Code: fmt.Sprintf("%v:%v", serviceCode, grpcMethod), GrpcMethod: grpcMethod, Protected: true}

		opt, ok := docsmap[v.Selector]
		if ok {
			act.DisplayName = opt.GetSummary()
			act.Description = opt.GetDescription()
		}

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
