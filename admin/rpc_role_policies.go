package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/policies"
	"github.com/grpc-kit/pkg/lion/rolepolicies"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func lionRolePolicyToProto(in *lion.RolePolicies, includePolicy bool) *adminv1.RolePolicyBinding {
	if in == nil {
		return nil
	}
	out := &adminv1.RolePolicyBinding{
		Id:          int64(in.ID),
		RoleId:      int64(in.RoleID),
		PolicyId:    int64(in.PolicyID),
		Metadata:    in.Metadata,
		Description: in.Description,
		CreatedBy:   in.CreatedBy,
		UpdatedBy:   in.UpdatedBy,
		CreatedAt:   timestamppb.New(in.CreatedAt),
		UpdatedAt:   timestamppb.New(in.UpdatedAt),
	}
	if includePolicy && in.Edges.LionPolicies != nil {
		out.Policy = buildPolicyProto(in.Edges.LionPolicies, includePolicy && in.Edges.LionPolicies != nil)
	}
	return out
}

func (a *KnownAdminAPI) rolePolicyForUpdate(ctx context.Context, db *lion.Client, roleID int, binding *adminv1.RolePolicyBinding) (*lion.RolePolicies, error) {
	if binding.GetId() > 0 {
		rp, err := db.RolePolicies.Get(ctx, int(binding.GetId()))
		if err != nil {
			if lion.IsNotFound(err) {
				return nil, errs.NotFound(ctx).WithMessage("role policy not found")
			}
			return nil, err
		}
		if rp.RoleID != roleID {
			return nil, errs.InvalidArgument(ctx).WithMessage("role_policy id does not belong to this role")
		}
		if binding.GetPolicyId() > 0 && int(binding.GetPolicyId()) != rp.PolicyID {
			return nil, errs.InvalidArgument(ctx).WithMessage("policy_id does not match role_policy record")
		}
		return rp, nil
	}

	policyID := binding.GetPolicyId()
	if policyID == 0 && binding.GetPolicy() != nil {
		policyID = binding.GetPolicy().GetId()
	}
	if policyID <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("policy_id or id is required")
	}

	rp, err := db.RolePolicies.Query().
		Where(rolepolicies.RoleIDEQ(roleID), rolepolicies.PolicyIDEQ(int(policyID))).
		Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("role policy not found")
		}
		return nil, err
	}
	return rp, nil
}

func (a *KnownAdminAPI) ListRolePolicies(ctx context.Context, req *adminv1.ListRolePoliciesRequest) (*adminv1.ListRolePoliciesResponse, error) {
	result := &adminv1.ListRolePoliciesResponse{Policies: make([]*adminv1.RolePolicyBinding, 0)}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	roleID, err := strconv.Atoi(req.GetParent())
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body parent is invalid")
	}
	if err := a.checkRolePermission(ctx, db, roleID); err != nil {
		return nil, err
	}

	query := db.RolePolicies.Query().Where(rolepolicies.RoleIDEQ(roleID))
	filter := strings.TrimSpace(req.GetFilter())
	if filter != "" {
		query = query.Where(rolepolicies.Or(
			rolepolicies.DescriptionContainsFold(filter),
			rolepolicies.HasLionPoliciesWith(
				policies.Or(
					policies.CodeContainsFold(filter),
					policies.DisplayNameContainsFold(filter),
					policies.DescriptionContainsFold(filter),
				),
			),
		))
	}

	switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
	case "created_at asc", "create_time asc":
		query = query.Order(lion.Asc(rolepolicies.FieldCreatedAt), lion.Asc(rolepolicies.FieldID))
	case "policy_id asc":
		query = query.Order(lion.Asc(rolepolicies.FieldPolicyID), lion.Asc(rolepolicies.FieldID))
	case "policy_id desc":
		query = query.Order(lion.Desc(rolepolicies.FieldPolicyID), lion.Asc(rolepolicies.FieldID))
	default:
		query = query.Order(lion.Desc(rolepolicies.FieldCreatedAt), lion.Asc(rolepolicies.FieldID))
	}

	totalSize, err := query.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	pageSize := GetPageSize(ctx, req.GetPageSize())
	switch p := req.GetPagination().(type) {
	case *adminv1.ListRolePoliciesRequest_Offset:
		query = query.Offset(int(p.Offset))
	case *adminv1.ListRolePoliciesRequest_PageToken:
		if req.GetPageToken() != "" {
			data, decErr := base64.StdEncoding.DecodeString(req.GetPageToken())
			if decErr != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token: %v", decErr))
			}
			var lastID int
			if jsonErr := json.Unmarshal(data, &lastID); jsonErr != nil {
				return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token format: %v", jsonErr))
			}
			if lastID > 0 {
				query = query.Where(rolepolicies.IDGT(lastID))
			}
		}
	}

	includePolicy := req.GetView() != adminv1.View_VIEW_BASIC
	if includePolicy {
		query = query.WithLionPolicies()
	}

	list, err := query.Limit(int(pageSize)).All(ctx)
	if err != nil {
		return nil, err
	}

	includeStatements := req.GetView() == adminv1.View_VIEW_FULL
	for _, item := range list {
		binding := lionRolePolicyToProto(item, includePolicy)
		if includePolicy && item.Edges.LionPolicies != nil {
			binding.Policy = buildPolicyProto(item.Edges.LionPolicies, includeStatements)
		}
		result.Policies = append(result.Policies, binding)
	}

	if _, ok := req.GetPagination().(*adminv1.ListRolePoliciesRequest_PageToken); ok && len(list) == int(pageSize) && len(list) > 0 {
		lastID := list[len(list)-1].ID
		tokenData, _ := json.Marshal(lastID)
		result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
	}

	return result, nil
}

func (a *KnownAdminAPI) CreateRolePolicies(ctx context.Context, req *adminv1.CreateRolePoliciesRequest) (*adminv1.CreateRolePoliciesResponse, error) {
	result := &adminv1.CreateRolePoliciesResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	roleID, err := strconv.Atoi(req.GetParent())
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body parent is invalid")
	}
	if err := a.checkRolePermission(ctx, db, roleID); err != nil {
		return nil, err
	}
	if len(req.GetPolicies()) == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("policies is empty")
	}

	var actor int64
	if v, err := GetUserID(ctx); err == nil {
		actor = v
	}

	for _, item := range req.GetPolicies() {
		policyID := item.GetPolicyId()
		if policyID == 0 && item.GetPolicy() != nil {
			policyID = item.GetPolicy().GetId()
		}
		if policyID <= 0 {
			return nil, errs.InvalidArgument(ctx).WithMessage("policy_id is required")
		}

		if _, err := db.Policies.Get(ctx, int(policyID)); err != nil {
			if lion.IsNotFound(err) {
				return nil, errs.NotFound(ctx).WithMessage("policy not found")
			}
			return nil, err
		}

		cb := db.RolePolicies.Create().
			SetRoleID(roleID).
			SetPolicyID(int(policyID)).
			SetDescription(item.GetDescription())
		if item.Metadata != nil {
			cb = cb.SetMetadata(item.Metadata)
		}
		if actor != 0 {
			cb = cb.SetCreatedBy(actor).SetUpdatedBy(actor)
		}
		if _, err := cb.Save(ctx); err != nil {
			if lion.IsConstraintError(err) {
				return nil, errs.AlreadyExists(ctx).WithMessage("role policy already exists")
			}
			return nil, err
		}
	}

	return result, nil
}

func (a *KnownAdminAPI) UpdateRolePolicies(ctx context.Context, req *adminv1.UpdateRolePoliciesRequest) (*adminv1.UpdateRolePoliciesResponse, error) {
	result := &adminv1.UpdateRolePoliciesResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	roleID, err := strconv.Atoi(req.GetParent())
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body parent is invalid")
	}
	if err := a.checkRolePermission(ctx, db, roleID); err != nil {
		return nil, err
	}
	if len(req.GetPolicies()) == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("policies is empty")
	}

	var actor int64
	if v, err := GetUserID(ctx); err == nil {
		actor = v
	}

	for _, item := range req.GetPolicies() {
		rp, err := a.rolePolicyForUpdate(ctx, db, roleID, item)
		if err != nil {
			return nil, err
		}

		upd := rp.Update().SetDescription(item.GetDescription()).SetMetadata(item.GetMetadata())
		if actor != 0 {
			upd = upd.SetUpdatedBy(actor)
		}
		if _, err := upd.Save(ctx); err != nil {
			return nil, err
		}
	}

	return result, nil
}

func (a *KnownAdminAPI) DeleteRolePolicy(ctx context.Context, req *adminv1.DeleteRolePolicyRequest) (*emptypb.Empty, error) {
	result := &emptypb.Empty{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	roleID, err := strconv.Atoi(req.GetParent())
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body parent is invalid")
	}
	if req.GetPolicyId() == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("policy_id is required")
	}
	if err := a.checkRolePermission(ctx, db, roleID); err != nil {
		return nil, err
	}

	if _, err := db.RolePolicies.Delete().
		Where(rolepolicies.RoleIDEQ(roleID), rolepolicies.PolicyIDEQ(int(req.GetPolicyId()))).
		Exec(ctx); err != nil {
		return nil, err
	}

	return result, nil
}
