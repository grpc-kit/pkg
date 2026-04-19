package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/policies"
	"github.com/grpc-kit/pkg/lion/policystatements"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/schema"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func lionPolicyStatementToProto(in *lion.PolicyStatements) *adminv1.PolicyStatement {
	if in == nil {
		return nil
	}
	return &adminv1.PolicyStatement{
		Id:               int64(in.ID),
		PolicyId:         int64(in.PolicyID),
		Sid:              in.Sid,
		Effect:           adminv1.PolicyStatement_Effect(in.Effect),
		ActionSelector:   in.ActionSelector,
		ResourceSelector: in.ResourceSelector,
		ConditionJson:    in.ConditionJSON,
		Priority:         int32(in.Priority),
		Description:      in.Description,
		CreatedBy:        in.CreatedBy,
		UpdatedBy:        in.UpdatedBy,
		CreatedAt:        timestamppb.New(in.CreatedAt),
		UpdatedAt:        timestamppb.New(in.UpdatedAt),
	}
}

func (a *KnownAdminAPI) GetPolicyStatement(ctx context.Context, req *adminv1.GetPolicyStatementRequest) (*adminv1.PolicyStatement, error) {
	if req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("statement id is required")
	}
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	obj, err := db.PolicyStatements.Get(ctx, int(req.GetId()))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("policy statement not found")
	}
	return lionPolicyStatementToProto(obj), nil
}

func (a *KnownAdminAPI) ListPolicyStatements(ctx context.Context, req *adminv1.ListPolicyStatementsRequest) (*adminv1.ListPolicyStatementsResponse, error) {
	result := &adminv1.ListPolicyStatementsResponse{}
	db, err := a.GetLionClient()
	if err != nil {
		return result, nil
	}

	where := make([]predicate.PolicyStatements, 0)
	if req.GetPolicyId() != 0 {
		where = append(where, policystatements.PolicyIDEQ(int(req.GetPolicyId())))
	}
	query := db.PolicyStatements.Query().Where(where...)
	if req.GetOrderBy() == "priority asc" {
		query = query.Order(lion.Asc(policystatements.FieldPriority), lion.Asc(policystatements.FieldCreatedAt))
	} else if req.GetOrderBy() == "priority desc" {
		query = query.Order(lion.Desc(policystatements.FieldPriority), lion.Desc(policystatements.FieldCreatedAt))
	} else {
		query = query.Order(lion.Asc(policystatements.FieldPriority), lion.Desc(policystatements.FieldCreatedAt))
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
			query = query.Where(policystatements.IDGT(lastID))
		}
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListPolicyStatementsRequest_Offset:
		query = query.Offset(int(p.Offset))
	case *adminv1.ListPolicyStatementsRequest_PageToken:
	}

	query = query.Limit(int(pageSize))
	list, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range list {
		result.Statements = append(result.Statements, lionPolicyStatementToProto(item))
	}

	switch req.GetPagination().(type) {
	case *adminv1.ListPolicyStatementsRequest_PageToken:
		if len(list) == int(pageSize) && len(list) > 0 {
			last := list[len(list)-1].ID
			tokenData, _ := json.Marshal(last)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}

	return result, nil
}

func (a *KnownAdminAPI) CreatePolicyStatement(ctx context.Context, req *adminv1.CreatePolicyStatementRequest) (*adminv1.PolicyStatement, error) {
	if req == nil || req.Statement == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body statement is nil")
	}
	if req.Statement.PolicyId <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("policy_id is required")
	}

	sid, err := schema.EnsureCode(req.Statement.Sid)
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	req.Statement.Sid = sid

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	if _, err := db.Policies.Query().Where(policies.IDEQ(int(req.Statement.PolicyId))).Only(ctx); err != nil {
		return nil, errs.NotFound(ctx).WithMessage("policy not found")
	}
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	obj, err := db.PolicyStatements.Create().
		SetPolicyID(int(req.Statement.PolicyId)).
		SetSid(req.Statement.Sid).
		SetEffect(int(req.Statement.Effect)).
		SetActionSelector(req.Statement.ActionSelector).
		SetResourceSelector(req.Statement.ResourceSelector).
		SetConditionJSON(req.Statement.ConditionJson).
		SetPriority(int(req.Statement.Priority)).
		SetDescription(req.Statement.Description).
		SetCreatedBy(userID).
		SetUpdatedBy(userID).
		Save(ctx)
	if err != nil {
		return nil, err
	}
	return lionPolicyStatementToProto(obj), nil
}

func (a *KnownAdminAPI) UpdatePolicyStatement(ctx context.Context, req *adminv1.UpdatePolicyStatementRequest) (*adminv1.PolicyStatement, error) {
	if req == nil || req.Statement == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body statement is nil")
	}
	if req.Statement.Id <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("statement id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}
	obj, err := db.PolicyStatements.Get(ctx, int(req.Statement.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("policy statement not found")
	}

	update := obj.Update().SetUpdatedBy(userID)
	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		for _, path := range req.UpdateMask.Paths {
			switch path {
			case "policy_id":
				update.SetPolicyID(int(req.Statement.PolicyId))
			case "sid":
				update.SetSid(req.Statement.Sid)
			case "effect":
				update.SetEffect(int(req.Statement.Effect))
			case "action_selector":
				update.SetActionSelector(req.Statement.ActionSelector)
			case "resource_selector":
				update.SetResourceSelector(req.Statement.ResourceSelector)
			case "condition_json":
				update.SetConditionJSON(req.Statement.ConditionJson)
			case "priority":
				update.SetPriority(int(req.Statement.Priority))
			case "description":
				update.SetDescription(req.Statement.Description)
			}
		}
	} else {
		update.
			SetPolicyID(int(req.Statement.PolicyId)).
			SetSid(req.Statement.Sid).
			SetEffect(int(req.Statement.Effect)).
			SetActionSelector(req.Statement.ActionSelector).
			SetResourceSelector(req.Statement.ResourceSelector).
			SetConditionJSON(req.Statement.ConditionJson).
			SetPriority(int(req.Statement.Priority)).
			SetDescription(req.Statement.Description)
	}

	saved, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}
	return lionPolicyStatementToProto(saved), nil
}

func (a *KnownAdminAPI) DeletePolicyStatement(ctx context.Context, req *adminv1.DeletePolicyStatementRequest) (*emptypb.Empty, error) {
	if req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("statement id is required")
	}
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	if err := db.PolicyStatements.DeleteOneID(int(req.GetId())).Exec(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
