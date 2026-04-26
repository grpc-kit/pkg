package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/resources"
	"github.com/grpc-kit/pkg/lion/resourcetypes"
	"github.com/grpc-kit/pkg/lion/services"
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
	result := &adminv1.ListServicesResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return result, nil
	}

	query := db.Services.Query()
	where := make([]predicate.Services, 0)
	if strings.TrimSpace(req.Filter) != "" {
		where = append(where, services.Or(
			services.CodeContainsFold(req.Filter),
			services.DisplayNameContainsFold(req.Filter),
			services.GrpcNameContainsFold(req.Filter),
		))
	}
	if len(where) > 0 {
		query = query.Where(where...)
	}

	switch req.OrderBy {
	case "code asc":
		query = query.Order(lion.Asc(services.FieldCode))
	case "code desc":
		query = query.Order(lion.Desc(services.FieldCode))
	case "create_time asc":
		query = query.Order(lion.Asc(services.FieldCreatedAt))
	default:
		query = query.Order(lion.Desc(services.FieldCreatedAt))
	}

	totalSize, err := query.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	pageSize := GetPageSizeByStructure(ctx, req.PageSize, req.Structure)
	var lastID int
	if req.GetPageToken() != "" {
		data, err := base64.StdEncoding.DecodeString(req.GetPageToken())
		if err != nil {
			return nil, fmt.Errorf("invalid page_token: %w", err)
		}
		if err := json.Unmarshal(data, &lastID); err != nil {
			return nil, fmt.Errorf("invalid page_token format: %w", err)
		}
		if lastID > 0 {
			query = query.Where(services.IDGT(lastID))
		}
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListServicesRequest_Offset:
		query = query.Offset(int(p.Offset))
	case *adminv1.ListServicesRequest_PageToken:
	}

	list, err := query.Limit(int(pageSize)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range list {
		result.Services = append(result.Services, lionServiceToProto(item))
	}
	if len(list) == int(pageSize) && len(list) > 0 {
		data, _ := json.Marshal(list[len(list)-1].ID)
		result.NextPageToken = base64.StdEncoding.EncodeToString(data)
	}
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
