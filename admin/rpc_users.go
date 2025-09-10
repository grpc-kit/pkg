package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/departmentusers"
	"github.com/grpc-kit/pkg/lion/users"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CreateUser 创建用户
func (a *KnownAdminAPI) CreateUser(ctx context.Context, req *adminv1.CreateUserRequest) (*adminv1.User, error) {
	result := &adminv1.User{}

	if req == nil || req.User == nil {
		return result, errs.InvalidArgument(ctx).
			WithMessage("request body user is nil")
	}

	if req.User.GetUsername() == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("username is empty")
	}

	// 只能在自己部门下创建，且为部门负责人
	userIDInt, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	// 默认查看所有用户（仅部门管理下所有可见）
	// 先找到 user 对应的 department_id
	leaders, err := a.config.db.DepartmentUsers.
		Query().
		Select(
			departmentusers.FieldID,
			departmentusers.FieldLeaderType,
			departmentusers.FieldDepartmentID,
			departmentusers.FieldUserID,
		).
		Where(departmentusers.UserID(userIDInt)).
		WithLionDepartments().
		All(ctx)
	if err != nil {
		return nil, err
	}

	if len(leaders) == 0 {
		return nil, errs.PermissionDenied(ctx).WithMessage("you are not allowed to create user")
	}

	// TODO；还需验证创建的用户必须是负责部门内

	userCreate := a.config.db.Users.Create()
	userCreate.SetUsername(req.User.GetUsername())

	if req.User.GetRealname() != "" {
		realname, err := crypto.EncryptAES(a.config.aesKey, []byte(req.User.GetRealname()))
		if err != nil {
			return nil, err
		}
		userCreate.SetRealnameEncrypted(realname)
	}
	if req.User.GetIdcard() != "" {
		idcard, err := crypto.EncryptAES(a.config.aesKey, []byte(req.User.GetIdcard()))
		if err != nil {
			return nil, err
		}
		userCreate.SetIdcardEncrypted(idcard)
	}
	if req.GetUser().GetNickname() != "" {
		userCreate.SetNickname(req.GetUser().GetNickname())
	}
	if req.GetUser().GetProfile() != "" {
		userCreate.SetProfile(req.GetUser().GetProfile())
	}
	if req.GetUser().GetPicture() != "" {
		userCreate.SetPicture(req.GetUser().GetPicture())
	}
	if req.GetUser().GetWebsite() != "" {
		userCreate.SetWebsite(req.GetUser().GetWebsite())
	}
	if req.GetUser().Email != "" {
		email, err := crypto.EncryptAES(a.config.aesKey, []byte(req.GetUser().GetEmail()))
		if err != nil {
			return nil, err
		}
		userCreate.SetEmailEncrypted(email)
	}
	if req.GetUser().PhoneNumber != nil {
		tmp, err := proto.Marshal(req.GetUser().GetPhoneNumber())
		if err == nil {
			phoneNumber, err := crypto.EncryptAES(a.config.aesKey, tmp)
			if err != nil {
				return nil, err
			}
			userCreate.SetPhoneNumberEncrypted(phoneNumber)
		}
	}
	if req.GetUser().Birthday == nil {
		// userCreate.SetBirthdate(time.)
	}
	if req.GetUser().GetDepartment() != nil {
		userCreate.SetDepartmentID(int(req.User.GetDepartment().GetId()))
	}

	thisUser, err := userCreate.Save(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value") {
			return nil, errs.AlreadyExists(ctx).
				WithLogger(a.logger, "create user err: %v", err).
				WithMessage("user already exists").
				WithMessageZHCN("你好，已存在!").Err()
		}

		return nil, errs.InvalidArgument(ctx).
			WithMessage("user create fail.").
			WithDetails(&errdetails.LocalizedMessage{Locale: "zh-CN", Message: "创建用户失败！"}).Err()
	}

	result = &adminv1.User{
		Id:          int32(thisUser.ID),
		Username:    thisUser.Username,
		Realname:    req.GetUser().Realname,
		Idcard:      req.GetUser().Idcard,
		Email:       req.GetUser().Email,
		PhoneNumber: req.GetUser().PhoneNumber,
		Nickname:    thisUser.Nickname,
		Profile:     thisUser.Profile,
		Picture:     thisUser.Picture,
	}

	return result, nil
}

// ListUsers 列出用户列表
func (a *KnownAdminAPI) ListUsers(ctx context.Context, req *adminv1.ListUsersRequest) (*adminv1.ListUsersResponse, error) {
	result := &adminv1.ListUsersResponse{}

	userIDInt, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	var selectViewFields []string

	basicViewFields := []string{
		users.FieldID,
		users.FieldUsername,
		users.FieldStatus,
		users.FieldNickname,
		users.FieldProfile,
		users.FieldPicture,
		users.FieldWebsite,
		users.FieldZoneinfo,
		users.FieldLocale,
	}

	fullViewFields := append(basicViewFields, []string{
		users.FieldRealnameEncrypted,
		users.FieldIdcardEncrypted,
		users.FieldEmailEncrypted,
		users.FieldEmailVerified,
		users.FieldGender,
		users.FieldBirthdate,
		users.FieldPhoneNumberEncrypted,
		users.FieldPhoneNumberVerified,
		users.FieldAddressEncrypted,
		users.FieldDepartmentID,
		users.FieldDescription,
	}...)

	switch req.GetView() {
	case adminv1.ListUsersRequest_USER_VIEW_FULL:
		selectViewFields = fullViewFields
	default:
		selectViewFields = basicViewFields
	}

	// 默认查看所有用户（仅部门管理下所有可见）
	// 先找到 user 对应的 department_id
	leaders, err := a.config.db.DepartmentUsers.
		Query().
		Select(
			departmentusers.FieldID,
			departmentusers.FieldLeaderType,
			departmentusers.FieldDepartmentID,
			departmentusers.FieldUserID,
		).
		Where(departmentusers.UserID(userIDInt)).
		WithLionDepartments().
		All(ctx)
	if err != nil {
		return nil, err
	}

	var allIDs []int
	for _, leader := range leaders {
		dept := leader.Edges.LionDepartments
		if dept == nil {
			continue
		}
		ids, err := a.getAllSubDeptIDs(ctx, dept.ID)
		if err != nil {
			return nil, err
		}
		allIDs = append(allIDs, ids...)
	}

	// TODO; 先简单提取部门 ID
	if req.GetFilter() != "" {
		departmentID, ok := a.getDepartmentID(req.GetFilter())
		if ok {
			// 判断该部门 ID 是否在 allIDs 中
			hasAllowDepartment := false
			for _, v := range allIDs {
				if v == departmentID {
					hasAllowDepartment = true
					break
				}
			}
			if !hasAllowDepartment {
				return result, errs.PermissionDenied(ctx).WithMessage("you are not allowed to view this department")
			}

			// 重新获取所有子部门
			allIDs, err = a.getAllSubDeptIDs(ctx, departmentID)
			if err != nil {
				return nil, err
			}
		}
	}

	// 查找用户并实现分页
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	var lastID int
	if req.GetPageToken() != "" {
		data, err := base64.StdEncoding.DecodeString(req.GetPageToken())
		if err != nil {
			return nil, fmt.Errorf("invalid page_token: %w", err)
		}
		if err := json.Unmarshal(data, &lastID); err != nil {
			return nil, fmt.Errorf("invalid page_token format: %w", err)
		}
	}

	userQuery := a.config.db.Users.Query()
	userQuery = userQuery.Where(users.DepartmentIDIn(allIDs...))
	if !req.GetShowDeleted() {
		userQuery = userQuery.Where(users.DeletedAtIsNil())
	}

	// OrderBy
	if req.GetOrderBy() != "" {
		switch req.GetOrderBy() {
		case "create_time desc":
			userQuery = userQuery.Order(lion.Desc(users.FieldCreatedAt))
		case "create_time asc":
			userQuery = userQuery.Order(lion.Asc(users.FieldCreatedAt))
		case "nickname asc":
			userQuery = userQuery.Order(lion.Asc(users.FieldNickname))
		case "nickname desc":
			userQuery = userQuery.Order(lion.Desc(users.FieldNickname))
		default:
			// 默认按 ID 升序
			userQuery = userQuery.Order(lion.Desc(users.FieldID))
		}
	} else {
		userQuery = userQuery.Order(lion.Desc(users.FieldID))
	}

	totalSize, err := userQuery.Count(ctx)
	if err != nil {
		return nil, err
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListUsersRequest_Offset:
		// Offset 分页
		userQuery = userQuery.Offset(int(p.Offset))
	case *adminv1.ListUsersRequest_PageToken:
		// Cursor 分页
		if lastID > 0 {
			userQuery = userQuery.Where(users.IDGT(lastID))
		}
	}

	userQuery = userQuery.Limit(pageSize)

	searchUsers, err := userQuery.Select(selectViewFields...).All(ctx)
	if err != nil {
		return nil, err
	}

	// --- 构造 next_page_token ---
	var nextPageToken string
	if len(searchUsers) == pageSize {
		last := searchUsers[len(searchUsers)-1].ID
		tokenData, _ := json.Marshal(last)
		nextPageToken = base64.StdEncoding.EncodeToString(tokenData)
	}

	result.NextPageToken = nextPageToken
	result.TotalSize = int32(totalSize)

	for _, user := range searchUsers {
		realname, _ := crypto.DecryptAES(a.config.aesKey, user.RealnameEncrypted)
		idcard, _ := crypto.DecryptAES(a.config.aesKey, user.IdcardEncrypted)
		email, _ := crypto.DecryptAES(a.config.aesKey, user.EmailEncrypted)
		phoneNumberByte, _ := crypto.DecryptAES(a.config.aesKey, user.PhoneNumberEncrypted)
		// address, _ := crypto.DecryptAES(a.config.aesKey, user.AddressEncrypted)

		var phoneNumber adminv1.PhoneNumber
		_ = proto.Unmarshal(phoneNumberByte, &phoneNumber)

		result.Users = append(result.Users, &adminv1.User{
			Id:                  int32(user.ID),
			Username:            user.Username,
			Status:              adminv1.UserStatus(user.Status),
			Realname:            string(realname),
			Idcard:              string(idcard),
			Nickname:            user.Nickname,
			Profile:             user.Profile,
			Picture:             user.Picture,
			Website:             user.Website,
			Email:               string(email),
			EmailVerified:       user.EmailVerified,
			Gender:              adminv1.Gender(user.Gender),
			Birthday:            timestamppb.New(user.Birthdate),
			Zoneinfo:            user.Zoneinfo,
			Locale:              user.Locale,
			PhoneNumber:         &phoneNumber,
			PhoneNumberVerified: user.PhoneNumberVerified,
			// Address:             address,
		})
	}

	return result, nil
}

// UpdateUser 更新用户信息
func (a *KnownAdminAPI) UpdateUser(ctx context.Context, req *adminv1.UpdateUserRequest) (*adminv1.User, error) {
	result := &adminv1.User{}

	return result, nil
}

func (a *KnownAdminAPI) getDepartmentID(filter string) (int, bool) {
	// 匹配形如 department_id==12 或 department_id == 12
	re := regexp.MustCompile(`department_id\s*==\s*(\d+)`)
	matches := re.FindStringSubmatch(filter)
	if len(matches) == 2 {
		val, err := strconv.Atoi(matches[1])
		if err != nil {
			return 0, false
		}
		return val, true
	}
	return 0, false
}
