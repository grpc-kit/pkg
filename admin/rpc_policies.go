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
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/rolepolicies"
	"github.com/grpc-kit/pkg/lion/schema"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func buildPolicyProto(entPolicy *lion.Policies, includeStatements bool) *adminv1.Policy {
	result := &adminv1.Policy{
		Id:          int64(entPolicy.ID),
		Code:        entPolicy.Code,
		DisplayName: entPolicy.DisplayName,
		Status:      adminv1.Policy_Status(entPolicy.PolicyStatus),
		Description: entPolicy.Description,
		Protected:   entPolicy.Protected,
		CreatedBy:   entPolicy.CreatedBy,
		UpdatedBy:   entPolicy.UpdatedBy,
		CreatedAt:   timestamppb.New(entPolicy.CreatedAt),
		UpdatedAt:   timestamppb.New(entPolicy.UpdatedAt),
	}

	if includeStatements {
		result.Statements = entPolicy.Statements
	}

	return result
}

// validatePolicyStatements 校验 statement 的必填字段，避免 protojson 静默丢失 enum
// 等问题导致的脏数据（典型场景：客户端发送 "Allow"/"Deny" 这类非规范字符串，
// 被 DiscardUnknown 配置丢成 EFFECT_UNSPECIFIED 后落库）。
func validatePolicyStatements(ctx context.Context, statements []*adminv1.PolicyStatement) error {
	for i, s := range statements {
		if s == nil {
			return errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("statements[%d] is nil", i))
		}
		if s.Effect != adminv1.PolicyStatement_ALLOW && s.Effect != adminv1.PolicyStatement_DENY {
			return errs.InvalidArgument(ctx).WithMessage(
				fmt.Sprintf("statements[%d].effect must be ALLOW or DENY, got %s", i, s.Effect.String()))
		}
		if len(s.Actions) == 0 {
			return errs.InvalidArgument(ctx).WithMessage(
				fmt.Sprintf("statements[%d].actions must not be empty", i))
		}
		if len(s.Resources) == 0 {
			return errs.InvalidArgument(ctx).WithMessage(
				fmt.Sprintf("statements[%d].resources must not be empty", i))
		}
	}
	return nil
}

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
	pageSize := GetPageSizeByStructure(ctx, req.PageSize, req.Structure)

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
	includeStatements := req.GetView() == adminv1.View_VIEW_FULL
	for _, p := range policyList {
		result.Policies = append(result.Policies, buildPolicyProto(p, includeStatements))
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

// GetPolicy 获取策略详情
func (a *KnownAdminAPI) GetPolicy(ctx context.Context, req *adminv1.GetPolicyRequest) (*adminv1.Policy, error) {
	if req == nil || req.GetCode() == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("policy code is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	policyEnt, err := db.Policies.Query().Where(policies.CodeEQ(req.GetCode())).First(ctx)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("policy not found")
	}

	includeStatements := req.GetView() != adminv1.View_VIEW_BASIC
	return buildPolicyProto(policyEnt, includeStatements), nil
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

	if err := validatePolicyStatements(ctx, req.Policy.Statements); err != nil {
		return nil, err
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 预检 code 是否已被占用，给出明确的 AlreadyExists 错误，
	// 同时仍依赖数据库 unique 索引兜底防止并发竞争写入。
	exists, err := db.Policies.Query().Where(policies.CodeEQ(req.Policy.Code)).Exist(ctx)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errs.AlreadyExists(ctx).WithMessage(fmt.Sprintf("policy code %q already exists", req.Policy.Code))
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
		SetPolicyStatus(int(req.Policy.Status)).
		SetDescription(req.Policy.Description).
		SetProtected(req.Policy.Protected).
		SetStatements(req.Policy.Statements).
		SetCreatedBy(userID).
		SetUpdatedBy(userID).
		Save(ctx)

	if err != nil {
		return nil, err
	}

	// 构建返回的策略对象
	return buildPolicyProto(newPolicy, true), nil
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
				// Code 创建后不可修改（见 Policy.code 注释）
				if req.Policy.Code != policy.Code {
					return nil, errs.InvalidArgument(ctx).WithMessage("policy code is immutable after creation")
				}
			case policies.FieldDisplayName:
				update.SetDisplayName(req.Policy.DisplayName)
			case policies.FieldPolicyStatus:
				update.SetPolicyStatus(int(req.Policy.Status))
			case policies.FieldDescription:
				update.SetDescription(req.Policy.Description)
			case policies.FieldProtected:
				update.SetProtected(req.Policy.Protected)
			case policies.FieldStatements:
				if err := validatePolicyStatements(ctx, req.Policy.Statements); err != nil {
					return nil, err
				}
				update.SetStatements(req.Policy.Statements)
			}
		}
		// 始终更新 UpdatedBy
		update.SetUpdatedBy(userID)
	} else {
		// 如果没有指定更新字段，则更新所有字段（code 仍不可修改）
		if req.Policy.Code != "" && req.Policy.Code != policy.Code {
			return nil, errs.InvalidArgument(ctx).WithMessage("policy code is immutable after creation")
		}
		if err := validatePolicyStatements(ctx, req.Policy.Statements); err != nil {
			return nil, err
		}
		update.
			SetDisplayName(req.Policy.DisplayName).
			SetPolicyStatus(int(req.Policy.Status)).
			SetDescription(req.Policy.Description).
			SetProtected(req.Policy.Protected).
			SetStatements(req.Policy.Statements).
			SetUpdatedBy(userID)
	}

	// 执行更新
	updatedPolicy, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}

	// 构建返回的策略对象
	return buildPolicyProto(updatedPolicy, true), nil
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

	policyEnt, err := db.Policies.Get(ctx, int(req.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("policy not found")
	}
	if policyEnt.Protected {
		return nil, errs.FailedPrecondition(ctx).WithMessage("protected policy cannot be deleted")
	}
	if db.RolePolicies.Query().Where(rolepolicies.PolicyIDEQ(int(req.Id))).CountX(ctx) > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("policy has role binding")
	}

	// 执行删除
	err = db.Policies.DeleteOneID(int(req.Id)).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
