package admin

import (
	"context"
	"strconv"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion/usergroups"
	"github.com/grpc-kit/pkg/lion/users"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/groups"
)

// CreateGroup 创建用户组
func (a *KnownAdminAPI) CreateGroup(ctx context.Context, req *adminv1.CreateGroupRequest) (*adminv1.Group, error) {
	result := &adminv1.Group{}

	if req.Group == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body group is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	group, err := db.Groups.Create().
		SetName(req.Group.Name).
		SetType(int(req.Group.Type.Number())).
		SetStatus(int(req.Group.Status.Number())).
		SetI18nName(I18NNameJSON(req.Group.I18NName)).
		SetOrderWeight(int(req.Group.OrderWeight)).
		SetParentID(int(req.Group.ParentId)).
		SetMaxMembers(int(req.Group.MaxMembers)).
		SetMetadata(MetadataJSON(req.Group.Metadata)).
		SetExternalID(req.Group.ExternalId).
		SetDepartmentID(int(req.Group.DepartmentId)).
		SetDescription(req.Group.Description).
		SetCreatedBy(int(req.Group.CreatedBy)).
		SetUpdatedBy(int(req.Group.UpdatedBy)).
		Save(ctx)
	if err != nil {
		return result, err
	}

	result = &adminv1.Group{
		Id:           int32(group.ID),
		Name:         group.Name,
		Type:         adminv1.Group_Type(group.Type),
		Status:       adminv1.Group_Status(group.Status),
		I18NName:     I18NNameParse(group.I18nName),
		OrderWeight:  int32(group.OrderWeight),
		ParentId:     int32(group.ParentID),
		MaxMembers:   int32(group.MaxMembers),
		Metadata:     MetadataParse(group.Metadata),
		ExternalId:   group.ExternalID,
		DepartmentId: int32(group.DepartmentID),
		Description:  group.Description,
		CreatedBy:    int32(group.CreatedBy),
		UpdatedBy:    int32(group.UpdatedBy),
	}

	return result, nil
}

// ListGroups 列出用户组
func (a *KnownAdminAPI) ListGroups(ctx context.Context, req *adminv1.ListGroupsRequest) (*adminv1.ListGroupsResponse, error) {
	result := &adminv1.ListGroupsResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 构建查询
	query := db.Groups.Query()

	// 默认按创建时间降序
	query = query.Order(lion.Desc(groups.FieldCreatedAt))

	// 执行查询
	groupList, err := query.All(ctx)
	if err != nil {
		return result, err
	}

	// 转换结果
	result.Groups = make([]*adminv1.Group, 0, len(groupList))
	for _, group := range groupList {
		result.Groups = append(result.Groups, &adminv1.Group{
			Id:           int32(group.ID),
			Name:         group.Name,
			Type:         adminv1.Group_Type(group.Type),
			Status:       adminv1.Group_Status(group.Status),
			I18NName:     I18NNameParse(group.I18nName),
			OrderWeight:  int32(group.OrderWeight),
			ParentId:     int32(group.ParentID),
			MaxMembers:   int32(group.MaxMembers),
			Metadata:     MetadataParse(group.Metadata),
			ExternalId:   group.ExternalID,
			DepartmentId: int32(group.DepartmentID),
			Description:  group.Description,
			CreatedBy:    int32(group.CreatedBy),
			UpdatedBy:    int32(group.UpdatedBy),
		})
	}

	return result, nil
}

// UpdateGroup 更新用户组
func (a *KnownAdminAPI) UpdateGroup(ctx context.Context, req *adminv1.UpdateGroupRequest) (*adminv1.Group, error) {
	result := &adminv1.Group{}

	if req.Group == nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body group is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 查找要更新的组
	group, err := db.Groups.Get(ctx, int(req.Group.Id))
	if err != nil {
		return result, err
	}

	// 构建更新操作
	update := group.Update()

	// 根据请求设置更新字段
	if req.UpdateMask != nil {
		for _, field := range req.UpdateMask.Paths {
			switch field {
			case "name":
				update.SetName(req.Group.Name)
			case "type":
				update.SetType(int(req.Group.Type.Number()))
			case "status":
				update.SetStatus(int(req.Group.Status.Number()))
			case "i18n_name":
				update.SetI18nName(I18NNameJSON(req.Group.I18NName))
			case "order_weight":
				update.SetOrderWeight(int(req.Group.OrderWeight))
			case "parent_id":
				update.SetParentID(int(req.Group.ParentId))
			case "max_members":
				update.SetMaxMembers(int(req.Group.MaxMembers))
			case "metadata":
				update.SetMetadata(MetadataJSON(req.Group.Metadata))
			case "external_id":
				update.SetExternalID(req.Group.ExternalId)
			case "department_id":
				update.SetDepartmentID(int(req.Group.DepartmentId))
			case "description":
				update.SetDescription(req.Group.Description)
			case "updated_by":
				update.SetUpdatedBy(int(req.Group.UpdatedBy))
			}
		}
	} else {
		// 如果没有指定更新字段，则更新所有非零字段
		update.
			SetName(req.Group.Name).
			SetType(int(req.Group.Type.Number())).
			SetStatus(int(req.Group.Status.Number())).
			SetI18nName(I18NNameJSON(req.Group.I18NName)).
			SetOrderWeight(int(req.Group.OrderWeight)).
			SetParentID(int(req.Group.ParentId)).
			SetMaxMembers(int(req.Group.MaxMembers)).
			SetMetadata(MetadataJSON(req.Group.Metadata)).
			SetExternalID(req.Group.ExternalId).
			SetDepartmentID(int(req.Group.DepartmentId)).
			SetDescription(req.Group.Description).
			SetUpdatedBy(int(req.Group.UpdatedBy))
	}

	// 执行更新
	updatedGroup, err := update.Save(ctx)
	if err != nil {
		return result, err
	}

	// 转换结果
	result = &adminv1.Group{
		Id:           int32(updatedGroup.ID),
		Name:         updatedGroup.Name,
		Type:         adminv1.Group_Type(updatedGroup.Type),
		Status:       adminv1.Group_Status(updatedGroup.Status),
		I18NName:     I18NNameParse(updatedGroup.I18nName),
		OrderWeight:  int32(updatedGroup.OrderWeight),
		ParentId:     int32(updatedGroup.ParentID),
		MaxMembers:   int32(updatedGroup.MaxMembers),
		Metadata:     MetadataParse(updatedGroup.Metadata),
		ExternalId:   updatedGroup.ExternalID,
		DepartmentId: int32(updatedGroup.DepartmentID),
		Description:  updatedGroup.Description,
		CreatedBy:    int32(updatedGroup.CreatedBy),
		UpdatedBy:    int32(updatedGroup.UpdatedBy),
	}

	return result, nil
}

// DeleteGroup 删除用户组
func (a *KnownAdminAPI) DeleteGroup(ctx context.Context, req *adminv1.DeleteGroupRequest) (*emptypb.Empty, error) {
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 执行删除
	err = db.Groups.DeleteOneID(int(req.Id)).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// ListGroupMembers 获取群组成员列表
func (a *KnownAdminAPI) ListGroupMembers(ctx context.Context, req *adminv1.ListGroupMembersRequest) (*adminv1.ListGroupMembersResponse, error) {
	result := &adminv1.ListGroupMembersResponse{
		GroupMembers: make([]*adminv1.UserGroup, 0),
	}

	if req.Parent == "" {
		return result, errs.InvalidArgument(ctx).WithMessage("request body parent is empty")
	}

	groupID, err := strconv.Atoi(req.Parent)
	if err != nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body parent is invalid")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	members, err := db.UserGroups.Query().Select(
		usergroups.FieldUserID,
		usergroups.FieldGroupID,
		usergroups.FieldRole,
		usergroups.FieldStatus,
		usergroups.FieldCreatedBy,
		usergroups.FieldUpdatedBy,
		usergroups.FieldCreatedAt,
		usergroups.FieldUpdatedAt,
		usergroups.FieldJoinedAt,
		usergroups.FieldDescription,
	).Where(
		usergroups.GroupIDEQ(groupID),
	).Order(
		lion.Desc(usergroups.FieldCreatedAt),
	).WithLionUsers(func(query *lion.UsersQuery) {
		query.Select(
			users.FieldID,
			users.FieldUsername,
			users.FieldNickname,
		)
	}).All(ctx)

	for _, member := range members {
		user := member.Edges.LionUsers
		if user == nil {
			continue
		}

		result.GroupMembers = append(result.GroupMembers, &adminv1.UserGroup{
			Id:        int32(member.ID),
			UserId:    int32(member.UserID),
			GroupId:   int32(member.GroupID),
			Role:      adminv1.UserGroup_Role(member.Role),
			Status:    adminv1.UserGroup_Status(member.Status),
			CreatedBy: int32(member.CreatedBy),
			UpdatedBy: int32(member.UpdatedBy),
			CreatedAt: timestamppb.New(member.CreatedAt),
			Username:  member.Edges.LionUsers.Username,
			Nickname:  member.Edges.LionUsers.Nickname,
		})
	}

	return result, nil
}
