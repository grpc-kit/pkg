package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
	"github.com/grpc-kit/pkg/lion/schema"
	"github.com/grpc-kit/pkg/lion/useridentities"
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
	/*
		userIDInt, err := GetUserID(ctx)
		if err != nil {
			return nil, err
		}
	*/

	// 默认查看所有用户（仅部门管理下所有可见）
	// 先找到 user 对应的 department_id
	/*
		leaders, err := a.config.db.UserDepartments.
			Query().
			Select(
				userdepartments.FieldID,
				userdepartments.FieldLeaderType,
				userdepartments.FieldDepartmentID,
				userdepartments.FieldUserID,
			).
			Where(userdepartments.UserID(userIDInt)).
			WithLionDepartments().
			All(ctx)
		if err != nil {
			return nil, err
		}
		if len(leaders) == 0 {
			return nil, errs.PermissionDenied(ctx).WithMessage("you are not allowed to create user")
		}
	*/

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
	if req.User.GetNationalId() != "" {
		idcard, err := crypto.EncryptAES(a.config.aesKey, []byte(req.User.GetNationalId()))
		if err != nil {
			return nil, err
		}
		userCreate.SetNationalIDEncrypted(idcard)
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
	/*
		if req.GetUser().GetDepartment() != nil {
			userCreate.SetDepartmentID(int(req.User.GetDepartment().GetId()))
		}
	*/

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
		Id:          int64(thisUser.ID),
		Username:    thisUser.Username,
		Realname:    req.GetUser().Realname,
		NationalId:  req.GetUser().NationalId,
		Email:       req.GetUser().Email,
		PhoneNumber: req.GetUser().PhoneNumber,
		Nickname:    thisUser.Nickname,
		Profile:     thisUser.Profile,
		Picture:     thisUser.Picture,
	}

	return result, nil
}

// ListUsers 获取用户列表
func (a *KnownAdminAPI) ListUsers(ctx context.Context, req *adminv1.ListUsersRequest) (*adminv1.ListUsersResponse, error) {
	result := &adminv1.ListUsersResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	var selectViewFields []string

	basicViewFields := []string{
		users.FieldID,
		users.FieldUsername,
		users.FieldUserStatus,
		users.FieldNickname,
		users.FieldProfile,
		users.FieldPicture,
		users.FieldWebsite,
		users.FieldTimezone,
		users.FieldLocale,
		users.FieldCreatedAt,
		users.FieldUpdatedAt,
	}

	fullViewFields := append(basicViewFields, []string{
		users.FieldRealnameEncrypted,
		users.FieldNationalIDEncrypted,
		users.FieldEmailEncrypted,
		users.FieldEmailVerified,
		users.FieldGender,
		users.FieldBirthdate,
		users.FieldPhoneNumberEncrypted,
		users.FieldPhoneNumberVerified,
		users.FieldAddressEncrypted,
		// users.FieldDepartmentID,
		users.FieldDescription,
	}...)

	switch req.GetView() {
	case adminv1.ListUsersRequest_USER_VIEW_FULL:
		selectViewFields = fullViewFields
	default:
		selectViewFields = basicViewFields
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

	userQuery := db.Users.Query()

	// 是否有过滤属性
	if req.GetFilterId() != "" {
		uid, err := strconv.Atoi(req.GetFilterId())
		if err != nil {
			return nil, fmt.Errorf("invalid filter_id: %w", err)
		}

		userQuery = userQuery.Where(users.IDEQ(uid))
	}
	if req.GetFilterUsername() != "" {
		userQuery = userQuery.Where(users.UsernameContains(req.GetFilterUsername()))
	}
	if req.GetFilterNickname() != "" {
		userQuery = userQuery.Where(users.NicknameContains(req.GetFilterNickname()))
	}
	if req.GetFilterStatus() != "" {
		status, err := strconv.Atoi(req.GetFilterStatus())
		if err != nil {
			return nil, fmt.Errorf("invalid filter_status: %w", err)
		}
		userQuery = userQuery.Where(users.UserStatusEQ(status))
	}
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
		idcard, _ := crypto.DecryptAES(a.config.aesKey, user.NationalIDEncrypted)
		email, _ := crypto.DecryptAES(a.config.aesKey, user.EmailEncrypted)
		phoneNumberByte, _ := crypto.DecryptAES(a.config.aesKey, user.PhoneNumberEncrypted)
		// address, _ := crypto.DecryptAES(a.config.aesKey, user.AddressEncrypted)

		var phoneNumber adminv1.PhoneNumber
		_ = proto.Unmarshal(phoneNumberByte, &phoneNumber)

		var birthday *timestamppb.Timestamp
		if user.Birthdate != nil {
			birthday = timestamppb.New(*user.Birthdate)
		}
		result.Users = append(result.Users, &adminv1.User{
			Id:                  int64(user.ID),
			Username:            user.Username,
			Status:              adminv1.User_Status(user.UserStatus),
			Realname:            string(realname),
			NationalId:          string(idcard),
			Nickname:            user.Nickname,
			Profile:             user.Profile,
			Picture:             user.Picture,
			Website:             user.Website,
			Email:               string(email),
			EmailVerified:       user.EmailVerified,
			Gender:              adminv1.User_Gender(user.Gender),
			Birthday:            birthday,
			Timezone:            user.Timezone,
			Locale:              user.Locale,
			PhoneNumber:         &phoneNumber,
			PhoneNumberVerified: user.PhoneNumberVerified,
			CreatedAt:           timestamppb.New(user.CreatedAt),
			UpdatedAt:           timestamppb.New(user.UpdatedAt),
			// Address:             address,
		})
	}

	return result, nil
}

// ListUsersV1 列出用户列表
/*
func (a *KnownAdminAPI) ListUsersV1(ctx context.Context, req *adminv1.ListUsersRequest) (*adminv1.ListUsersResponse, error) {
	result := &adminv1.ListUsersResponse{}

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
		users.FieldCreatedAt,
		users.FieldUpdatedAt,
	}

	fullViewFields := append(basicViewFields, []string{
		users.FieldRealnameEncrypted,
		users.FieldNationalIDEncrypted,
		users.FieldEmailEncrypted,
		users.FieldEmailVerified,
		users.FieldGender,
		users.FieldBirthdate,
		users.FieldPhoneNumberEncrypted,
		users.FieldPhoneNumberVerified,
		users.FieldAddressEncrypted,
		// users.FieldDepartmentID,
		users.FieldDescription,
	}...)

	switch req.GetView() {
	case adminv1.ListUsersRequest_USER_VIEW_FULL:
		selectViewFields = fullViewFields
	default:
		selectViewFields = basicViewFields
	}

	roleIDs, err := a.getUserRoleID(ctx)
	if err != nil {
		return nil, err
	}

	var allDepartmentIDs []int

	rdObj, err := a.config.db.RoleDepartments.Query().
		Select(
			roledepartments.FieldDepartmentID,
			roledepartments.FieldRoleID,
		).
		Where(
			roledepartments.RoleIDIn(roleIDs...),
		).All(ctx)
	if err != nil {
		return nil, err
	}

	for _, v := range rdObj {
		allDepartmentIDs = append(allDepartmentIDs, v.DepartmentID)
	}

	// TODO; 先简单提取部门 ID
	if req.GetFilter() != "" {
		departmentID, ok := a.getDepartmentID(req.GetFilter())
		if ok {
			// 判断该部门 ID 是否在 allIDs 中
			hasAllowDepartment := false
			for _, v := range allDepartmentIDs {
				if v == departmentID {
					hasAllowDepartment = true
					break
				}
			}
			if !hasAllowDepartment {
				return result, errs.PermissionDenied(ctx).WithMessage("you are not allowed to view this department")
			}

			// 重新获取所有子部门
			allDepartmentIDs, err = a.getAllSubDeptIDs(ctx, departmentID)
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

	allUserIDs := make([]int, 0)

	dps, err := a.config.db.UserDepartments.Query().
		Select(
			userdepartments.FieldUserID,
		).Where(
		userdepartments.DepartmentIDIn(allDepartmentIDs...),
	).All(ctx)
	if err != nil {
		return nil, err
	}
	for _, v := range dps {
		allUserIDs = append(allUserIDs, v.UserID)
	}

	userQuery := a.config.db.Users.Query()
	userQuery = userQuery.Where(users.IDIn(allUserIDs...))
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
		idcard, _ := crypto.DecryptAES(a.config.aesKey, user.NationalIDEncrypted)
		email, _ := crypto.DecryptAES(a.config.aesKey, user.EmailEncrypted)
		phoneNumberByte, _ := crypto.DecryptAES(a.config.aesKey, user.PhoneNumberEncrypted)
		// address, _ := crypto.DecryptAES(a.config.aesKey, user.AddressEncrypted)

		var phoneNumber adminv1.PhoneNumber
		_ = proto.Unmarshal(phoneNumberByte, &phoneNumber)

		var birthday *timestamppb.Timestamp
		if user.Birthdate != nil {
			birthday = timestamppb.New(*user.Birthdate)
		}
		result.Users = append(result.Users, &adminv1.User{
			Id:                  int64(user.ID),
			Username:            user.Username,
			Status:              adminv1.User_Status(user.Status),
			Realname:            string(realname),
			NationalId:          string(idcard),
			Nickname:            user.Nickname,
			Profile:             user.Profile,
			Picture:             user.Picture,
			Website:             user.Website,
			Email:               string(email),
			EmailVerified:       user.EmailVerified,
			Gender:              adminv1.User_Gender(user.Gender),
			Birthday:            birthday,
			Zoneinfo:            user.Zoneinfo,
			Locale:              user.Locale,
			PhoneNumber:         &phoneNumber,
			PhoneNumberVerified: user.PhoneNumberVerified,
			CreatedAt:           timestamppb.New(user.CreatedAt),
			UpdatedAt:           timestamppb.New(user.UpdatedAt),
			// Address:             address,
		})
	}

	return result, nil
}
*/

// UpdateUser 更新用户信息
func (a *KnownAdminAPI) UpdateUser(ctx context.Context, req *adminv1.UpdateUserRequest) (*adminv1.User, error) {
	result := &adminv1.User{}

	// TODO; 验证权限

	if req.UpdateMask != nil && len(req.UpdateMask.Paths) != 0 {
		x := a.config.db.Users.Update()

		for _, path := range req.UpdateMask.Paths {
			// a.logger.Infof("update mask path: %v", path)

			switch path {
			// 基本信息
			case users.FieldUsername:
				x.SetUsername(req.User.Username)
			case users.FieldNickname:
				x.SetNickname(req.User.Nickname)
			case users.FieldProfile:
				x.SetProfile(req.User.Profile)
			case users.FieldPicture:
				x.SetPicture(req.User.Picture)
			case users.FieldWebsite:
				x.SetWebsite(req.User.Website)
			case users.FieldTimezone:
				x.SetTimezone(req.User.Timezone)
			case users.FieldLocale:
				x.SetLocale(req.User.Locale)
			case users.FieldUserType:
				x.SetUserType(int(req.User.Type))
			case users.FieldUserStatus:
				x.SetUserStatus(int(req.User.Status))

				// 身份信息
			case users.FieldGender:
				x.SetGender(int(req.User.Gender))
			case schema.FieldNameNormalize(users.FieldRealnameEncrypted):
				encBody, err := crypto.EncryptAES(a.config.aesKey, []byte(req.User.Realname))
				if err == nil {
					x.SetRealnameEncrypted(encBody)
				}
			case schema.FieldNameNormalize(users.FieldNationalIDEncrypted):
				encBody, err := crypto.EncryptAES(a.config.aesKey, []byte(req.User.NationalId))
				if err == nil {
					x.SetNationalIDEncrypted(encBody)
				}
			case users.FieldBirthdate:
				x.SetBirthdate(req.User.Birthday.AsTime())

				// 联系信息
			case users.FieldEmailVerified:
				x.SetEmailVerified(req.User.EmailVerified)
			case schema.FieldNameNormalize(users.FieldEmailEncrypted):
				encBody, err := crypto.EncryptAES(a.config.aesKey, []byte(req.User.Email))
				if err == nil {
					x.SetEmailEncrypted(encBody)
				}
			case users.FieldPhoneNumberVerified:
				x.SetPhoneNumberVerified(req.User.PhoneNumberVerified)
			case "phone_number.national_number":
				rawBody, err := proto.Marshal(req.User.PhoneNumber)
				if err != nil {
					continue
				}
				encBody, err := crypto.EncryptAES(a.config.aesKey, rawBody)
				if err == nil {
					x.SetPhoneNumberEncrypted(encBody)
				}

				// 地址信息
			case "address.street_address":
				rawBody, err := proto.Marshal(req.User.Address)
				if err != nil {
					continue
				}
				encBody, err := crypto.EncryptAES(a.config.aesKey, rawBody)
				if err == nil {
					x.SetAddressEncrypted(encBody)
				}
			}
		}

		_, err := x.Where(users.IDEQ(int(req.User.Id))).Save(ctx)
		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// GetUser 获取用户详情
func (a *KnownAdminAPI) GetUser(ctx context.Context, req *adminv1.GetUserRequest) (*adminv1.User, error) {
	var selectViewFields []string

	basicViewFields := []string{
		users.FieldID,
		users.FieldUsername,
		users.FieldUserStatus,
		users.FieldNickname,
		users.FieldProfile,
		users.FieldPicture,
		users.FieldWebsite,
		users.FieldTimezone,
		users.FieldLocale,
	}

	fullViewFields := append(basicViewFields, []string{
		users.FieldRealnameEncrypted,
		users.FieldNationalIDEncrypted,
		users.FieldEmailEncrypted,
		users.FieldEmailVerified,
		users.FieldGender,
		users.FieldBirthdate,
		users.FieldPhoneNumberEncrypted,
		users.FieldPhoneNumberVerified,
		users.FieldAddressEncrypted,
		users.FieldDescription,
	}...)

	selectViewFields = fullViewFields

	// TODO; 验证权限
	row, err := a.config.db.Users.Query().
		Select(selectViewFields...).
		Where(users.IDEQ(int(req.Id))).
		Only(ctx)
	if err != nil {
		return nil, err
	}

	var phoneNumber adminv1.PhoneNumber
	phoneNumberByte := crypto.DecryptAESMust(a.config.aesKey, row.PhoneNumberEncrypted)
	_ = proto.Unmarshal(phoneNumberByte, &phoneNumber)

	var address adminv1.Address
	addressByte := crypto.DecryptAESMust(a.config.aesKey, row.AddressEncrypted)
	_ = proto.Unmarshal(addressByte, &address)

	var birthday *timestamppb.Timestamp
	if row.Birthdate != nil {
		birthday = timestamppb.New(*row.Birthdate)
	}
	result := &adminv1.User{
		Id:                  int64(row.ID),
		Username:            row.Username,
		Status:              adminv1.User_Status(row.UserStatus),
		Realname:            string(crypto.DecryptAESMust(a.config.aesKey, row.RealnameEncrypted)),
		NationalId:          string(crypto.DecryptAESMust(a.config.aesKey, row.NationalIDEncrypted)),
		Nickname:            row.Nickname,
		Profile:             row.Profile,
		Picture:             row.Picture,
		Website:             row.Website,
		Email:               string(crypto.DecryptAESMust(a.config.aesKey, row.EmailEncrypted)),
		EmailVerified:       row.EmailVerified,
		Gender:              adminv1.User_Gender(row.Gender),
		Birthday:            birthday,
		Timezone:            row.Timezone,
		Locale:              row.Locale,
		PhoneNumber:         &phoneNumber,
		PhoneNumberVerified: row.PhoneNumberVerified,
		Address:             &address,
	}

	return result, nil
}

// UpdateUserPassword 修改用户密码
func (a *KnownAdminAPI) UpdateUserPassword(ctx context.Context, req *adminv1.UpdateUserPasswordRequest) (*adminv1.UpdateUserPasswordResponse, error) {
	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}

	provider, err := tx.AuthProviders.Query().
		Select(
			authproviders.FieldName,
		).
		Where(authproviders.ProviderTypeEQ(int(adminv1.AuthProvider_TYPE_LOCAL.Number()))).
		WithLionUserIdentities(func(q *lion.UserIdentitiesQuery) {
			q.Select(
				useridentities.FieldID,
				useridentities.FieldUserID,
				useridentities.FieldProviderID,
				useridentities.FieldProviderUserID,
			).Where(
				useridentities.UserIDEQ(int(req.UserId)),
			)
		}).
		Only(ctx)
	if err != nil {
		defer tx.Rollback()
		return nil, err
	}

	// 不存在则新建
	if len(provider.Edges.LionUserIdentities) == 0 {
		tx.UserIdentities.Create().
			SetUserID(int(req.UserId)).
			SetProviderID(provider.ID).
			SetProviderUserID(strconv.Itoa(int(req.UserId))).
			SetPasswordChangedAt(time.Now()).
			SetPasswordHash(crypto.BcryptHashMust(req.NewPasswordHash)).Save(ctx)
	} else {
		tx.UserIdentities.Update().
			SetPasswordChangedAt(time.Now()).
			SetPasswordHash(crypto.BcryptHashMust(req.NewPasswordHash)).
			Where(
				useridentities.UserIDEQ(int(req.UserId)),
				useridentities.ProviderIDEQ(provider.ID),
			).Save(ctx)
	}

	tx.Commit()

	return &adminv1.UpdateUserPasswordResponse{}, nil
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
