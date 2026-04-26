package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/actions"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/schema"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func lionActionToProto(in *lion.Actions) *adminv1.Action {
	if in == nil {
		return nil
	}
	return &adminv1.Action{
		Id:                int64(in.ID),
		Code:              in.Code,
		DisplayName:       in.DisplayName,
		ResourceType:      adminv1.Resource_Type(in.ResourceType),
		ProjectionMapping: in.ProjectionMapping,
		Protected:         in.Protected,
		Description:       in.Description,
		CreatedBy:         in.CreatedBy,
		UpdatedBy:         in.UpdatedBy,
		CreatedAt:         timestamppb.New(in.CreatedAt),
		UpdatedAt:         timestamppb.New(in.UpdatedAt),
	}
}

// validateProjectionMapping 校验 projection_mapping 是否为合法 JSON
func validateProjectionMapping(raw string) (string, error) {
	if raw == "" {
		return "{}", nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return "", fmt.Errorf("projection_mapping must be valid JSON: %w", err)
	}
	return raw, nil
}

func (a *KnownAdminAPI) GetAction(ctx context.Context, req *adminv1.GetActionRequest) (*adminv1.Action, error) {
	if req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("action id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	obj, err := db.Actions.Get(ctx, int(req.GetId()))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("action not found")
	}
	return lionActionToProto(obj), nil
}

func (a *KnownAdminAPI) ListActions(ctx context.Context, req *adminv1.ListActionsRequest) (*adminv1.ListActionsResponse, error) {
	result := &adminv1.ListActionsResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return result, nil
	}

	where := make([]predicate.Actions, 0)
	if req.GetResourceType() != 0 {
		resourceType, err := a.resolveResourceTypeForLegacy(ctx, db, adminv1.Resource_Type(req.GetResourceType()))
		if err != nil {
			return result, nil
		}
		where = append(where, actions.ResourceTypeIDEQ(resourceType.ID))
	}

	query := db.Actions.Query().Where(where...)
	if req.GetOrderBy() == "code asc" {
		query = query.Order(lion.Asc(actions.FieldCode))
	} else if req.GetOrderBy() == "code desc" {
		query = query.Order(lion.Desc(actions.FieldCode))
	} else {
		query = query.Order(lion.Desc(actions.FieldCreatedAt))
	}

	totalSize, err := query.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	pageSize := GetPageSizeByStructure(ctx, req.GetPageSize(), req.GetStructure())
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
			query = query.Where(actions.IDGT(lastID))
		}
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListActionsRequest_Offset:
		query = query.Offset(int(p.Offset))
	case *adminv1.ListActionsRequest_PageToken:
	}

	query = query.Limit(int(pageSize))
	list, err := query.All(ctx)
	if err != nil {
		return nil, err
	}

	for _, item := range list {
		result.Actions = append(result.Actions, lionActionToProto(item))
	}

	switch req.GetPagination().(type) {
	case *adminv1.ListActionsRequest_PageToken:
		if len(list) == int(pageSize) && len(list) > 0 {
			last := list[len(list)-1].ID
			tokenData, _ := json.Marshal(last)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}

	return result, nil
}

func (a *KnownAdminAPI) CreateAction(ctx context.Context, req *adminv1.CreateActionRequest) (*adminv1.Action, error) {
	if req == nil || req.Action == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body action is nil")
	}

	code, err := schema.EnsureCode(req.Action.Code)
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	req.Action.Code = code

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}
	resourceType, err := a.resolveResourceTypeForLegacy(ctx, db, req.Action.ResourceType)
	if err != nil {
		return nil, err
	}

	projMapping, err := validateProjectionMapping(req.Action.ProjectionMapping)
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	obj, err := db.Actions.Create().
		SetCode(req.Action.Code).
		SetDisplayName(req.Action.DisplayName).
		SetResourceType(int(req.Action.ResourceType)).
		SetResourceTypeID(resourceType.ID).
		SetProjectionMapping(projMapping).
		SetProtected(req.Action.Protected).
		SetDescription(req.Action.Description).
		SetCreatedBy(userID).
		SetUpdatedBy(userID).
		Save(ctx)
	if err != nil {
		return nil, err
	}

	return lionActionToProto(obj), nil
}

func (a *KnownAdminAPI) UpdateAction(ctx context.Context, req *adminv1.UpdateActionRequest) (*adminv1.Action, error) {
	if req == nil || req.Action == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body action is nil")
	}
	if req.Action.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("action id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	obj, err := db.Actions.Get(ctx, int(req.Action.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("action not found")
	}

	update := obj.Update().SetUpdatedBy(userID)
	resolvedResourceTypeID := obj.ResourceTypeID
	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		for _, path := range req.UpdateMask.Paths {
			switch path {
			case "code":
				update.SetCode(req.Action.Code)
			case "display_name":
				update.SetDisplayName(req.Action.DisplayName)
			case "resource_type":
				resourceType, err := a.resolveResourceTypeForLegacy(ctx, db, req.Action.ResourceType)
				if err != nil {
					return nil, err
				}
				update.SetResourceType(int(req.Action.ResourceType))
				update.SetResourceTypeID(resourceType.ID)
				resolvedResourceTypeID = resourceType.ID
			case "projection_mapping":
				pm, err := validateProjectionMapping(req.Action.ProjectionMapping)
				if err != nil {
					return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
				}
				update.SetProjectionMapping(pm)
			case "protected":
				update.SetProtected(req.Action.Protected)
			case "description":
				update.SetDescription(req.Action.Description)
			}
		}
	} else {
		resourceType, err := a.resolveResourceTypeForLegacy(ctx, db, req.Action.ResourceType)
		if err != nil {
			return nil, err
		}
		pm, err := validateProjectionMapping(req.Action.ProjectionMapping)
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
		}
		update.
			SetCode(req.Action.Code).
			SetDisplayName(req.Action.DisplayName).
			SetResourceType(int(req.Action.ResourceType)).
			SetResourceTypeID(resourceType.ID).
			SetProjectionMapping(pm).
			SetProtected(req.Action.Protected).
			SetDescription(req.Action.Description)
		resolvedResourceTypeID = resourceType.ID
	}

	saved, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}
	saved.ResourceTypeID = resolvedResourceTypeID
	return lionActionToProto(saved), nil
}

func (a *KnownAdminAPI) DeleteAction(ctx context.Context, req *adminv1.DeleteActionRequest) (*emptypb.Empty, error) {
	if req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("action id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	obj, err := db.Actions.Get(ctx, int(req.GetId()))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("action not found")
	}
	if obj.Protected {
		return nil, errs.InvalidArgument(ctx).WithMessage("protected action can not be deleted")
	}
	if err := db.Actions.DeleteOneID(obj.ID).Exec(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
