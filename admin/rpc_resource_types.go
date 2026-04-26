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
	"github.com/grpc-kit/pkg/lion/actions"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/resources"
	"github.com/grpc-kit/pkg/lion/resourcetypes"
	"github.com/grpc-kit/pkg/lion/services"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func lionResourceTypeToProto(in *lion.ResourceTypes) *adminv1.ResourceType {
	if in == nil {
		return nil
	}
	return &adminv1.ResourceType{
		Id:          int64(in.ID),
		Code:        in.Code,
		DisplayName: in.DisplayName,
		ServiceCode: in.ServiceCode,
		Description: in.Description,
		Protected:   in.Protected,
		CreatedBy:   in.CreatedBy,
		UpdatedBy:   in.UpdatedBy,
		CreatedAt:   timestamppb.New(in.CreatedAt),
		UpdatedAt:   timestamppb.New(in.UpdatedAt),
	}
}

func (a *KnownAdminAPI) ListResourceTypes(ctx context.Context, req *adminv1.ListResourceTypesRequest) (*adminv1.ListResourceTypesResponse, error) {
	result := &adminv1.ListResourceTypesResponse{}
	db, err := a.GetLionClient()
	if err != nil {
		return result, nil
	}
	query := db.ResourceTypes.Query()
	where := make([]predicate.ResourceTypes, 0)
	if req.GetServiceCode() != "" {
		where = append(where, resourcetypes.ServiceCodeEQ(req.GetServiceCode()))
	}
	if strings.TrimSpace(req.Filter) != "" {
		where = append(where, resourcetypes.Or(
			resourcetypes.CodeContainsFold(req.Filter),
			resourcetypes.DisplayNameContainsFold(req.Filter),
		))
	}
	if len(where) > 0 {
		query = query.Where(where...)
	}
	switch req.OrderBy {
	case "code asc":
		query = query.Order(lion.Asc(resourcetypes.FieldCode))
	case "code desc":
		query = query.Order(lion.Desc(resourcetypes.FieldCode))
	case "create_time asc":
		query = query.Order(lion.Asc(resourcetypes.FieldCreatedAt))
	default:
		query = query.Order(lion.Desc(resourcetypes.FieldCreatedAt))
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
			query = query.Where(resourcetypes.IDGT(lastID))
		}
	}
	switch p := req.GetPagination().(type) {
	case *adminv1.ListResourceTypesRequest_Offset:
		query = query.Offset(int(p.Offset))
	case *adminv1.ListResourceTypesRequest_PageToken:
	}
	list, err := query.Limit(int(pageSize)).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range list {
		result.ResourceTypes = append(result.ResourceTypes, lionResourceTypeToProto(item))
	}
	if len(list) == int(pageSize) && len(list) > 0 {
		data, _ := json.Marshal(list[len(list)-1].ID)
		result.NextPageToken = base64.StdEncoding.EncodeToString(data)
	}
	return result, nil
}

func (a *KnownAdminAPI) CreateResourceType(ctx context.Context, req *adminv1.CreateResourceTypeRequest) (*adminv1.ResourceType, error) {
	if req == nil || req.ResourceType == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body resource_type is nil")
	}
	code := strings.TrimSpace(req.ResourceType.Code)
	if code == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("resource type code is required")
	}
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	serviceCode := strings.TrimSpace(req.ResourceType.ServiceCode)
	if serviceCode != "" {
		exists, err := db.Services.Query().Where(services.CodeEQ(serviceCode)).Exist(ctx)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, errs.InvalidArgument(ctx).WithMessage("service_code not found")
		}
	}
	obj, err := db.ResourceTypes.Create().
		SetCode(code).
		SetDisplayName(req.ResourceType.DisplayName).
		SetServiceCode(serviceCode).
		SetDescription(req.ResourceType.Description).
		SetProtected(false).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return lionResourceTypeToProto(obj), nil
}

func (a *KnownAdminAPI) UpdateResourceType(ctx context.Context, req *adminv1.UpdateResourceTypeRequest) (*adminv1.ResourceType, error) {
	if req == nil || req.ResourceType == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body resource_type is nil")
	}
	if req.ResourceType.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("resource type id is required")
	}
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	obj, err := db.ResourceTypes.Get(ctx, int(req.ResourceType.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("resource type not found")
	}
	validateServiceCode := func(code string) error {
		if code == "" {
			return nil
		}
		exists, err := db.Services.Query().Where(services.CodeEQ(code)).Exist(ctx)
		if err != nil {
			return err
		}
		if !exists {
			return errs.InvalidArgument(ctx).WithMessage("service_code not found")
		}
		return nil
	}
	update := obj.Update()
	apply := func(path string) error {
		switch path {
		case "code":
			code := strings.TrimSpace(req.ResourceType.Code)
			if code == "" {
				return errs.InvalidArgument(ctx).WithMessage("resource type code is required")
			}
			update.SetCode(code)
		case "display_name":
			update.SetDisplayName(req.ResourceType.DisplayName)
		case "service_code":
			serviceCode := strings.TrimSpace(req.ResourceType.ServiceCode)
			if err := validateServiceCode(serviceCode); err != nil {
				return err
			}
			update.SetServiceCode(serviceCode)
		case "description":
			update.SetDescription(req.ResourceType.Description)
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
		update.SetDisplayName(req.ResourceType.DisplayName)
		if err := apply("service_code"); err != nil {
			return nil, err
		}
		update.SetDescription(req.ResourceType.Description)
	}
	saved, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}
	return lionResourceTypeToProto(saved), nil
}

func (a *KnownAdminAPI) DeleteResourceType(ctx context.Context, req *adminv1.DeleteResourceTypeRequest) (*emptypb.Empty, error) {
	if req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("resource type id is required")
	}
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	obj, err := db.ResourceTypes.Get(ctx, int(req.GetId()))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("resource type not found")
	}
	if obj.Protected {
		return nil, errs.InvalidArgument(ctx).WithMessage("protected resource type can not be deleted")
	}
	usedByResources, err := db.Resources.Query().Where(resources.ResourceTypeIDEQ(obj.ID)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if usedByResources {
		return nil, errs.InvalidArgument(ctx).WithMessage("resource type is referenced by resources")
	}
	usedByActions, err := db.Actions.Query().Where(actions.ResourceTypeIDEQ(obj.ID)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if usedByActions {
		return nil, errs.InvalidArgument(ctx).WithMessage("resource type is referenced by actions")
	}
	if err := db.ResourceTypes.DeleteOneID(obj.ID).Exec(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
