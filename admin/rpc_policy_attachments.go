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
	"github.com/grpc-kit/pkg/lion/policyattachments"
	"github.com/grpc-kit/pkg/lion/predicate"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func lionPolicyAttachmentToProto(in *lion.PolicyAttachments) *adminv1.PolicyAttachment {
	if in == nil {
		return nil
	}
	var expiresAt *timestamppb.Timestamp
	if in.ExpiresAt != nil {
		expiresAt = timestamppb.New(*in.ExpiresAt)
	}
	return &adminv1.PolicyAttachment{
		Id:            int64(in.ID),
		PolicyId:      int64(in.PolicyID),
		PrincipalType: adminv1.PolicyAttachment_PrincipalType(adminv1.PolicyAttachment_PrincipalType_value[in.PrincipalType]),
		PrincipalId:   in.PrincipalID,
		ResourceId:    in.ResourceID,
		IsRecursive:   in.IsRecursive,
		Status:        adminv1.PolicyAttachment_Status(in.AttachmentStatus),
		ConditionJson: in.ConditionJSON,
		ExpiresAt:     expiresAt,
		Description:   in.Description,
		CreatedBy:     in.CreatedBy,
		UpdatedBy:     in.UpdatedBy,
		CreatedAt:     timestamppb.New(in.CreatedAt),
		UpdatedAt:     timestamppb.New(in.UpdatedAt),
	}
}

func attachmentPrincipalTypeToString(v adminv1.PolicyAttachment_PrincipalType) string {
	switch v {
	case adminv1.PolicyAttachment_USER:
		return "USER"
	case adminv1.PolicyAttachment_ROLE:
		return "ROLE"
	case adminv1.PolicyAttachment_GROUP:
		return "GROUP"
	case adminv1.PolicyAttachment_DEPARTMENT:
		return "DEPARTMENT"
	case adminv1.PolicyAttachment_SERVICE_ACCOUNT:
		return "SERVICE_ACCOUNT"
	case adminv1.PolicyAttachment_CLIENT_APP:
		return "CLIENT_APP"
	case adminv1.PolicyAttachment_TENANT:
		return "TENANT"
	default:
		return ""
	}
}

func (a *KnownAdminAPI) GetPolicyAttachment(ctx context.Context, req *adminv1.GetPolicyAttachmentRequest) (*adminv1.PolicyAttachment, error) {
	if req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("attachment id is required")
	}
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	obj, err := db.PolicyAttachments.Get(ctx, int(req.GetId()))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("policy attachment not found")
	}
	return lionPolicyAttachmentToProto(obj), nil
}

func (a *KnownAdminAPI) ListPolicyAttachments(ctx context.Context, req *adminv1.ListPolicyAttachmentsRequest) (*adminv1.ListPolicyAttachmentsResponse, error) {
	result := &adminv1.ListPolicyAttachmentsResponse{}
	db, err := a.GetLionClient()
	if err != nil {
		return result, nil
	}

	where := make([]predicate.PolicyAttachments, 0)
	if req.GetPolicyId() != 0 {
		where = append(where, policyattachments.PolicyIDEQ(int(req.GetPolicyId())))
	}
	if req.GetPrincipalId() != 0 {
		where = append(where, policyattachments.PrincipalIDEQ(req.GetPrincipalId()))
	}
	if req.GetPrincipalType() != adminv1.PolicyAttachment_PRINCIPAL_TYPE_UNSPECIFIED {
		where = append(where, policyattachments.PrincipalTypeEQ(attachmentPrincipalTypeToString(req.GetPrincipalType())))
	}

	query := db.PolicyAttachments.Query().Where(where...).Order(lion.Desc(policyattachments.FieldCreatedAt))
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
			query = query.Where(policyattachments.IDGT(lastID))
		}
	}
	switch p := req.GetPagination().(type) {
	case *adminv1.ListPolicyAttachmentsRequest_Offset:
		query = query.Offset(int(p.Offset))
	case *adminv1.ListPolicyAttachmentsRequest_PageToken:
	}
	query = query.Limit(int(pageSize))

	list, err := query.All(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range list {
		result.Attachments = append(result.Attachments, lionPolicyAttachmentToProto(item))
	}

	switch req.GetPagination().(type) {
	case *adminv1.ListPolicyAttachmentsRequest_PageToken:
		if len(list) == int(pageSize) && len(list) > 0 {
			last := list[len(list)-1].ID
			tokenData, _ := json.Marshal(last)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}
	return result, nil
}

func (a *KnownAdminAPI) CreatePolicyAttachment(ctx context.Context, req *adminv1.CreatePolicyAttachmentRequest) (*adminv1.PolicyAttachment, error) {
	if req == nil || req.Attachment == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body attachment is nil")
	}
	if req.Attachment.PolicyId <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("policy_id is required")
	}
	if req.Attachment.PrincipalId <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("principal_id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	if _, err := db.Policies.Query().Where(policies.IDEQ(int(req.Attachment.PolicyId))).Only(ctx); err != nil {
		return nil, errs.NotFound(ctx).WithMessage("policy not found")
	}
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	builder := db.PolicyAttachments.Create().
		SetPolicyID(int(req.Attachment.PolicyId)).
		SetPrincipalType(attachmentPrincipalTypeToString(req.Attachment.PrincipalType)).
		SetPrincipalID(req.Attachment.PrincipalId).
		SetResourceID(req.Attachment.ResourceId).
		SetIsRecursive(req.Attachment.IsRecursive).
		SetAttachmentStatus(int(req.Attachment.Status)).
		SetConditionJSON(req.Attachment.ConditionJson).
		SetDescription(req.Attachment.Description).
		SetCreatedBy(userID).
		SetUpdatedBy(userID)
	if req.Attachment.ExpiresAt != nil {
		v := req.Attachment.ExpiresAt.AsTime()
		builder.SetExpiresAt(v)
	}

	obj, err := builder.Save(ctx)
	if err != nil {
		return nil, err
	}
	return lionPolicyAttachmentToProto(obj), nil
}

func (a *KnownAdminAPI) UpdatePolicyAttachment(ctx context.Context, req *adminv1.UpdatePolicyAttachmentRequest) (*adminv1.PolicyAttachment, error) {
	if req == nil || req.Attachment == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body attachment is nil")
	}
	if req.Attachment.Id <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("attachment id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}
	obj, err := db.PolicyAttachments.Get(ctx, int(req.Attachment.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("policy attachment not found")
	}

	update := obj.Update().SetUpdatedBy(userID)
	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		for _, path := range req.UpdateMask.Paths {
			switch path {
			case "policy_id":
				update.SetPolicyID(int(req.Attachment.PolicyId))
			case "principal_type":
				update.SetPrincipalType(attachmentPrincipalTypeToString(req.Attachment.PrincipalType))
			case "principal_id":
				update.SetPrincipalID(req.Attachment.PrincipalId)
			case "resource_id":
				update.SetResourceID(req.Attachment.ResourceId)
			case "is_recursive":
				update.SetIsRecursive(req.Attachment.IsRecursive)
			case "status":
				update.SetAttachmentStatus(int(req.Attachment.Status))
			case "condition_json":
				update.SetConditionJSON(req.Attachment.ConditionJson)
			case "description":
				update.SetDescription(req.Attachment.Description)
			case "expires_at":
				if req.Attachment.ExpiresAt != nil {
					update.SetExpiresAt(req.Attachment.ExpiresAt.AsTime())
				} else {
					update.ClearExpiresAt()
				}
			}
		}
	} else {
		update.
			SetPolicyID(int(req.Attachment.PolicyId)).
			SetPrincipalType(attachmentPrincipalTypeToString(req.Attachment.PrincipalType)).
			SetPrincipalID(req.Attachment.PrincipalId).
			SetResourceID(req.Attachment.ResourceId).
			SetIsRecursive(req.Attachment.IsRecursive).
			SetAttachmentStatus(int(req.Attachment.Status)).
			SetConditionJSON(req.Attachment.ConditionJson).
			SetDescription(req.Attachment.Description)
		if req.Attachment.ExpiresAt != nil {
			update.SetExpiresAt(req.Attachment.ExpiresAt.AsTime())
		} else {
			update.ClearExpiresAt()
		}
	}

	saved, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}
	return lionPolicyAttachmentToProto(saved), nil
}

func (a *KnownAdminAPI) DeletePolicyAttachment(ctx context.Context, req *adminv1.DeletePolicyAttachmentRequest) (*emptypb.Empty, error) {
	if req.GetId() <= 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("attachment id is required")
	}
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}
	if err := db.PolicyAttachments.DeleteOneID(int(req.GetId())).Exec(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}
