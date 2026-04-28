package admin

import (
	"context"
	"fmt"
	"strings"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/resources"
	"github.com/grpc-kit/pkg/lion/resourcetypes"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func lionServiceToProto(in *lion.Services) *adminv1.Service {
	if in == nil {
		return nil
	}
	return &adminv1.Service{
		Id:          int64(in.ID),
		Code:        in.Code,
		GrpcName:    in.GrpcName,
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
		&adminv1.Service{Id: 1, Code: codeName1, GrpcName: strings.Join(temp1[:6], "."), DisplayName: xxx.Title, Protected: true},
	)

	yyy, err := a.getMicroserviceGatewayServiceConfig()
	if err != nil {
		return nil, err
	}

	grpcName2 := yyy.Http.GetRules()[0].Selector
	temp2 := strings.Split(grpcName2, ".")
	codeName2 := fmt.Sprintf("%v.%v.%v", temp2[3], temp2[4], temp2[2])

	result.Services = append(result.Services,
		&adminv1.Service{Id: 2, Code: codeName2, GrpcName: strings.Join(temp2[:6], "."), DisplayName: yyy.Title, Protected: true},
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

func (a *KnownAdminAPI) CreateService(ctx context.Context, req *adminv1.CreateServiceRequest) (*adminv1.Service, error) {
	if req == nil || req.Service == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body service is nil")
	}
	code := strings.TrimSpace(req.Service.Code)
	grpcName := strings.TrimSpace(req.Service.GrpcName)
	if code == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("service code is required")
	}
	if grpcName == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("grpc_name is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	obj, err := db.Services.Create().
		SetCode(code).
		SetGrpcName(grpcName).
		SetDisplayName(req.Service.DisplayName).
		SetDescription(req.Service.Description).
		SetProtected(false).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return lionServiceToProto(obj), nil
}

func (a *KnownAdminAPI) UpdateService(ctx context.Context, req *adminv1.UpdateServiceRequest) (*adminv1.Service, error) {
	if req == nil || req.Service == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body service is nil")
	}
	if req.Service.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("service id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	obj, err := db.Services.Get(ctx, int(req.Service.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("service not found")
	}

	update := obj.Update()
	apply := func(path string) error {
		switch path {
		case "code":
			code := strings.TrimSpace(req.Service.Code)
			if code == "" {
				return errs.InvalidArgument(ctx).WithMessage("service code is required")
			}
			update.SetCode(code)
		case "grpc_name":
			grpcName := strings.TrimSpace(req.Service.GrpcName)
			if grpcName == "" {
				return errs.InvalidArgument(ctx).WithMessage("grpc_name is required")
			}
			update.SetGrpcName(grpcName)
		case "display_name":
			update.SetDisplayName(req.Service.DisplayName)
		case "description":
			update.SetDescription(req.Service.Description)
		case "protected":
			return errs.InvalidArgument(ctx).WithMessage("protected field is managed by system")
		}
		return nil
	}

	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		for _, path := range req.UpdateMask.Paths {
			if err := apply(path); err != nil {
				return nil, err
			}
		}
	} else {
		if err := apply("code"); err != nil {
			return nil, err
		}
		if err := apply("grpc_name"); err != nil {
			return nil, err
		}
		update.SetDisplayName(req.Service.DisplayName)
		update.SetDescription(req.Service.Description)
	}

	saved, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}
	return lionServiceToProto(saved), nil
}

func (a *KnownAdminAPI) DeleteService(ctx context.Context, req *adminv1.DeleteServiceRequest) (*emptypb.Empty, error) {
	if req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("service id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	obj, err := db.Services.Get(ctx, int(req.GetId()))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("service not found")
	}
	if obj.Protected {
		return nil, errs.InvalidArgument(ctx).WithMessage("protected service can not be deleted")
	}
	usedByTypes, err := db.ResourceTypes.Query().Where(resourcetypes.ServiceCodeEQ(obj.Code)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if usedByTypes {
		return nil, errs.InvalidArgument(ctx).WithMessage("service is referenced by resource types")
	}
	usedByResources, err := db.Resources.Query().Where(resources.ServiceCodeEQ(obj.Code)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if usedByResources {
		return nil, errs.InvalidArgument(ctx).WithMessage("service is referenced by resources")
	}
	if err := db.Services.DeleteOneID(obj.ID).Exec(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
