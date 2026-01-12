package admin

import (
	"context"
	"strconv"
	"time"

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

	departmentID := int(req.Group.DepartmentId)
	if departmentID == 0 {
		departmentID = 1
	}

	group, err := db.Groups.Create().
		SetCode(req.Group.Code).
		SetGroupType(int(req.Group.Type.Number())).
		SetGroupStatus(int(req.Group.Status.Number())).
		// SetI18nName(req.Group.I18NName).
		SetSortOrder(int(req.Group.SortOrder)).
		SetParentID(int(req.Group.ParentId)).
		SetMaxMembers(int(req.Group.MaxMembers)).
		SetMetadata(req.Group.Metadata).
		SetExternalID(req.Group.ExternalId).
		SetDepartmentID(departmentID).
		SetDescription(req.Group.Description).
		SetCreatedBy(int64(int(req.Group.CreatedBy))).
		SetUpdatedBy(int64(int(req.Group.UpdatedBy))).
		Save(ctx)
	if err != nil {
		return result, err
	}

	result = &adminv1.Group{
		Id:     int32(group.ID),
		Code:   group.Code,
		Type:   adminv1.Group_Type(group.GroupType),
		Status: adminv1.Group_Status(group.GroupStatus),
		// I18NName:     group.I18nName,
		DisplayName:  group.DisplayName,
		SortOrder:    int32(group.SortOrder),
		ParentId:     int32(group.ParentID),
		MaxMembers:   int32(group.MaxMembers),
		Metadata:     group.Metadata,
		ExternalId:   group.ExternalID,
		DepartmentId: int32(departmentID),
		Description:  group.Description,
		CreatedBy:    group.CreatedBy,
		UpdatedBy:    group.UpdatedBy,
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
			Code:         group.Code,
			Type:         adminv1.Group_Type(group.GroupType),
			Status:       adminv1.Group_Status(group.GroupStatus),
			DisplayName:  group.DisplayName,
			SortOrder:    int32(group.SortOrder),
			ParentId:     int32(group.ParentID),
			MaxMembers:   int32(group.MaxMembers),
			Metadata:     group.Metadata,
			ExternalId:   group.ExternalID,
			DepartmentId: int32(group.DepartmentID),
			Description:  group.Description,
			CreatedBy:    group.CreatedBy,
			UpdatedBy:    group.UpdatedBy,
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
			case "code":
				update.SetCode(req.Group.Code)
			case "type":
				update.SetGroupType(int(req.Group.Type.Number()))
			case "status":
				update.SetGroupStatus(int(req.Group.Status.Number()))
				/*
					case "i18n_name":
						update.SetI18nName(req.Group.I18NName)
				*/
			case groups.FieldSortOrder:
				update.SetSortOrder(int(req.Group.SortOrder))
			case "parent_id":
				update.SetParentID(int(req.Group.ParentId))
			case "max_members":
				update.SetMaxMembers(int(req.Group.MaxMembers))
			case "metadata":
				update.SetMetadata(req.Group.Metadata)
			case "external_id":
				update.SetExternalID(req.Group.ExternalId)
			case "department_id":
				update.SetDepartmentID(int(req.Group.DepartmentId))
			case "description":
				update.SetDescription(req.Group.Description)
			case "updated_by":
				update.SetUpdatedBy(int64(int(req.Group.UpdatedBy)))
			}
		}
	} else {
		// 如果没有指定更新字段，则更新所有非零字段
		update.
			SetCode(req.Group.Code).
			SetGroupType(int(req.Group.Type.Number())).
			SetGroupStatus(int(req.Group.Status.Number())).
			// SetI18nName(req.Group.I18NName).
			SetSortOrder(int(req.Group.SortOrder)).
			SetParentID(int(req.Group.ParentId)).
			SetMaxMembers(int(req.Group.MaxMembers)).
			SetMetadata(req.Group.Metadata).
			SetExternalID(req.Group.ExternalId).
			SetDepartmentID(int(req.Group.DepartmentId)).
			SetDescription(req.Group.Description).
			SetUpdatedBy(int64(int(req.Group.UpdatedBy)))
	}

	// 执行更新
	updatedGroup, err := update.Save(ctx)
	if err != nil {
		return result, err
	}

	// 转换结果
	result = &adminv1.Group{
		Id:     int32(updatedGroup.ID),
		Code:   updatedGroup.Code,
		Type:   adminv1.Group_Type(updatedGroup.GroupType),
		Status: adminv1.Group_Status(updatedGroup.GroupStatus),
		// I18NName:     updatedGroup.I18nName,
		SortOrder:    int32(updatedGroup.SortOrder),
		ParentId:     int32(updatedGroup.ParentID),
		MaxMembers:   int32(updatedGroup.MaxMembers),
		Metadata:     updatedGroup.Metadata,
		ExternalId:   updatedGroup.ExternalID,
		DepartmentId: int32(updatedGroup.DepartmentID),
		Description:  updatedGroup.Description,
		CreatedBy:    updatedGroup.CreatedBy,
		UpdatedBy:    updatedGroup.UpdatedBy,
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
		GroupMembers: make([]*adminv1.GroupMember, 0),
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
		usergroups.FieldMemberRole,
		usergroups.FieldMemberStatus,
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

		result.GroupMembers = append(result.GroupMembers, &adminv1.GroupMember{
			Id:           int32(member.ID),
			UserId:       int64(member.UserID),
			Username:     member.Edges.LionUsers.Username,
			Nickname:     member.Edges.LionUsers.Nickname,
			GroupId:      int32(member.GroupID),
			MemberRole:   adminv1.GroupMember_Role(member.MemberRole),
			MemberStatus: adminv1.GroupMember_Status(member.MemberStatus),
			JoinedAt:     timestamppb.New(member.JoinedAt),
			ExpiredAt:    timestamppb.New(member.ExpiredAt),
			CreatedBy:    member.CreatedBy,
			UpdatedBy:    member.UpdatedBy,
			CreatedAt:    timestamppb.New(member.CreatedAt),
			UpdatedAt:    timestamppb.New(member.UpdatedAt),
			Description:  member.Description,
		})
	}

	return result, nil
}

// CreateGroupMembers 创建群组成员
func (a *KnownAdminAPI) CreateGroupMembers(ctx context.Context, req *adminv1.CreateGroupMembersRequest) (*adminv1.CreateGroupMembersResponse, error) {
	result := &adminv1.CreateGroupMembersResponse{}

	if req.Parent == "" {
		return result, errs.InvalidArgument(ctx).WithMessage("request body parent is empty")
	}

	userID, err := GetUserID(ctx)
	if err != nil {
		return result, err
	}

	groupID, err := strconv.Atoi(req.Parent)
	if err != nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body parent is invalid")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	allMembers := make([]*lion.UserGroupsCreate, 0)

	for _, member := range req.GroupMembers {
		user := db.UserGroups.Create().
			SetUserID(int(member.UserId)).
			SetGroupID(groupID).
			SetMemberRole(int(member.MemberRole)).
			SetMemberStatus(int(member.MemberStatus)).
			SetCreatedBy(int64(userID)).
			SetUpdatedBy(int64(userID)).
			SetJoinedAt(time.Now()).
			SetDescription(member.Description)

		allMembers = append(allMembers, user)
	}

	_, err = db.UserGroups.CreateBulk(allMembers...).Save(ctx)
	if err != nil {
		return result, err
	}

	return result, nil
}

// DeleteGroupMember 删除群组成员
func (a *KnownAdminAPI) DeleteGroupMember(ctx context.Context, req *adminv1.DeleteGroupMemberRequest) (*emptypb.Empty, error) {
	groupID, err := strconv.Atoi(req.Parent)
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body parent is invalid")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	// 执行删除
	_, err = db.UserGroups.Delete().
		Where(
			usergroups.GroupID(groupID),
			usergroups.UserID(int(req.UserId)),
		).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// UpdateGroupMember 更新群组成员
func (a *KnownAdminAPI) UpdateGroupMember(ctx context.Context, req *adminv1.UpdateGroupMemberRequest) (*adminv1.GroupMember, error) {
	result := &adminv1.GroupMember{}

	if req.Parent == "" {
		return result, errs.InvalidArgument(ctx).WithMessage("request body parent is empty")
	}

	userID, err := GetUserID(ctx)
	if err != nil {
		return result, err
	}

	groupID, err := strconv.Atoi(req.Parent)
	if err != nil {
		return result, errs.InvalidArgument(ctx).WithMessage("request body parent is invalid")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	if req.UpdateMask != nil && len(req.UpdateMask.Paths) != 0 {
		x := db.UserGroups.Update()

		for _, field := range req.UpdateMask.Paths {
			switch field {
			case usergroups.FieldMemberRole:
				x.SetMemberRole(int(req.GroupMember.MemberRole))
			case usergroups.FieldMemberStatus:
				x.SetMemberStatus(int(req.GroupMember.MemberStatus))
			case usergroups.FieldDescription:
				x.SetDescription(req.GroupMember.Description)
			}
		}

		x.SetUpdatedBy(int64(userID)).
			SetUpdatedAt(time.Now()).Where(
			usergroups.GroupIDEQ(groupID),
			usergroups.UserIDEQ(int(req.UserId)),
		).Save(ctx)
	}

	return result, nil
}
