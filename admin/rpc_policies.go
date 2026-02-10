package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/permissions"
	"github.com/grpc-kit/pkg/lion/policies"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/schema"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ListPolicies 获取策略列表
func (a *KnownAdminAPI) ListPolicies(ctx context.Context, req *adminv1.ListPoliciesRequest) (*adminv1.ListPoliciesResponse, error) {
	result := &adminv1.ListPoliciesResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		// 如果未开启数据库时直接返回空结果而不是错误
		return result, nil
	}

	// 构建查询条件
	policiesWhere := make([]predicate.Policies, 0)

	// 过滤条件
	if req.PolicyType != 0 {
		policiesWhere = append(policiesWhere, policies.PolicyTypeEQ(int(req.PolicyType)))
	}
	if req.PolicyStatus != 0 {
		policiesWhere = append(policiesWhere, policies.PolicyStatusEQ(int(req.PolicyStatus)))
	}

	// 构建查询，但先不执行
	policyQuery := db.Policies.Query().Where(policiesWhere...)

	// 处理排序
	if req.OrderBy != "" {
		switch req.OrderBy {
		case "create_time desc":
			policyQuery = policyQuery.Order(lion.Desc(policies.FieldCreatedAt))
		case "create_time asc":
			policyQuery = policyQuery.Order(lion.Asc(policies.FieldCreatedAt))
		case "code desc":
			policyQuery = policyQuery.Order(lion.Desc(policies.FieldCode))
		case "code asc":
			policyQuery = policyQuery.Order(lion.Asc(policies.FieldCode))
		default:
			// 默认按创建时间降序
			policyQuery = policyQuery.Order(lion.Desc(policies.FieldCreatedAt))
		}
	} else {
		// 默认排序
		policyQuery = policyQuery.Order(lion.Desc(policies.FieldCreatedAt))
	}

	// 计算总数（在应用分页前）
	totalSize, err := policyQuery.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	// 处理分页
	pageSize := GetPageSize(ctx, req.PageSize)

	var lastID int
	if req.GetPageToken() != "" {
		// Cursor-based 分页
		data, err := base64.StdEncoding.DecodeString(req.GetPageToken())
		if err != nil {
			return nil, fmt.Errorf("invalid page_token: %w", err)
		}
		if err := json.Unmarshal(data, &lastID); err != nil {
			return nil, fmt.Errorf("invalid page_token format: %w", err)
		}
		if lastID > 0 {
			policyQuery = policyQuery.Where(policies.IDGT(lastID))
		}
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListPoliciesRequest_Offset:
		// Offset-based 分页
		policyQuery = policyQuery.Offset(int(p.Offset))
	case *adminv1.ListPoliciesRequest_PageToken:
		// Cursor-based 分页已在上面处理
	}

	// 应用 Limit
	policyQuery = policyQuery.Limit(int(pageSize))

	// 执行查询
	policyList, err := policyQuery.All(ctx)
	if err != nil {
		return nil, err
	}

	// 转换为响应格式
	for _, p := range policyList {
		policy := &adminv1.Policy{
			Id:          int64(p.ID),
			Code:        p.Code,
			DisplayName: p.DisplayName,
			Type:        adminv1.Policy_Type(p.PolicyType),
			Status:      adminv1.Policy_Status(p.PolicyStatus),
			Value:       p.Value,
			Description: p.Description,
		}

		result.Policies = append(result.Policies, policy)
	}

	// 构造 next_page_token（仅用于 cursor-based 分页）
	switch req.GetPagination().(type) {
	case *adminv1.ListPoliciesRequest_PageToken:
		// 只有在使用 cursor-based 分页时才生成 next_page_token
		if len(policyList) == int(pageSize) && len(policyList) > 0 {
			last := policyList[len(policyList)-1].ID
			tokenData, _ := json.Marshal(last)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}

	return result, nil
}

// CreatePolicy 创建策略
func (a *KnownAdminAPI) CreatePolicy(ctx context.Context, req *adminv1.CreatePolicyRequest) (*adminv1.Policy, error) {
	if req == nil || req.Policy == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body policy is nil")
	}

	code, err := schema.EnsureCode(req.Policy.Code)
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	req.Policy.Code = code

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 获取创建者用户 ID
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	// 创建策略
	newPolicy, err := db.Policies.Create().
		SetCode(req.Policy.Code).
		SetDisplayName(req.Policy.DisplayName).
		SetPolicyType(int(req.Policy.Type)).
		SetPolicyStatus(int(req.Policy.Status)).
		SetValue(req.Policy.Value).
		SetDescription(req.Policy.Description).
		SetCreatedBy(userID).
		SetUpdatedBy(userID).
		Save(ctx)

	if err != nil {
		return nil, err
	}

	// 构建返回的策略对象
	result := &adminv1.Policy{
		Id:          int64(newPolicy.ID),
		Code:        newPolicy.Code,
		DisplayName: newPolicy.DisplayName,
		Type:        adminv1.Policy_Type(newPolicy.PolicyType),
		Status:      adminv1.Policy_Status(newPolicy.PolicyStatus),
		Value:       newPolicy.Value,
		Description: newPolicy.Description,
	}

	return result, nil
}

// UpdatePolicy 更新策略
func (a *KnownAdminAPI) UpdatePolicy(ctx context.Context, req *adminv1.UpdatePolicyRequest) (*adminv1.Policy, error) {
	if req == nil || req.Policy == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body policy is nil")
	}

	if req.Policy.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("policy id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 获取更新者用户 ID
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	// 查找要更新的策略
	policy, err := db.Policies.Get(ctx, int(req.Policy.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("policy not found")
	}

	// 构建更新操作
	update := policy.Update()

	// 根据请求设置更新字段
	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		for _, field := range req.UpdateMask.Paths {
			switch field {
			case policies.FieldCode:
				update.SetCode(req.Policy.Code)
			case policies.FieldDisplayName:
				update.SetDisplayName(req.Policy.DisplayName)
			case policies.FieldPolicyType:
				update.SetPolicyType(int(req.Policy.Type))
			case policies.FieldPolicyStatus:
				update.SetPolicyStatus(int(req.Policy.Status))
			case policies.FieldValue:
				update.SetValue(req.Policy.Value)
			case policies.FieldDescription:
				update.SetDescription(req.Policy.Description)
			}
		}
		// 始终更新 UpdatedBy
		update.SetUpdatedBy(userID)
	} else {
		// 如果没有指定更新字段，则更新所有字段
		update.
			SetCode(req.Policy.Code).
			SetDisplayName(req.Policy.DisplayName).
			SetPolicyType(int(req.Policy.Type)).
			SetPolicyStatus(int(req.Policy.Status)).
			SetValue(req.Policy.Value).
			SetDescription(req.Policy.Description).
			SetUpdatedBy(userID)
	}

	// 执行更新
	updatedPolicy, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}

	// 构建返回的策略对象
	result := &adminv1.Policy{
		Id:          int64(updatedPolicy.ID),
		Code:        updatedPolicy.Code,
		DisplayName: updatedPolicy.DisplayName,
		Type:        adminv1.Policy_Type(updatedPolicy.PolicyType),
		Status:      adminv1.Policy_Status(updatedPolicy.PolicyStatus),
		Value:       updatedPolicy.Value,
		Description: updatedPolicy.Description,
	}

	return result, nil
}

// DeletePolicy 删除策略
func (a *KnownAdminAPI) DeletePolicy(ctx context.Context, req *adminv1.DeletePolicyRequest) (*emptypb.Empty, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("policy id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 检查策略是否存在
	_, err = db.Policies.Get(ctx, int(req.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("policy not found")
	}

	// 检查是否存在关联的权限（通过 lion_permissions 表）
	permissionsCount, err := db.Permissions.Query().
		Where(permissions.PolicyIDEQ(int(req.Id))).
		Count(ctx)
	if err != nil {
		return nil, err
	}

	if permissionsCount > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("cannot delete policy with associated permissions")
	}

	// 执行删除
	err = db.Policies.DeleteOneID(int(req.Id)).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
