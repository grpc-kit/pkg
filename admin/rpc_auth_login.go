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
	"github.com/grpc-kit/pkg/lion/authproviders"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/schema"
	"google.golang.org/protobuf/types/known/emptypb"
)

// CreateAuthLogin 创建登录认证
func (a *KnownAdminAPI) CreateAuthLogin(ctx context.Context, req *adminv1.CreateAuthLoginRequest) (*adminv1.AuthToken, error) {
	result := &adminv1.AuthToken{TokenType: "Bearer"}

	var accessToken string

	if req.Username == "" {
		return nil, errs.Unauthenticated(ctx)
	}

	// TODO; 不允许创建过长过期的 token
	expiresIn := req.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 24 * 60 * 60
	}

	hasDBEnabled := false
	db, err := a.GetLionClient()
	if err == nil && db != nil {
		hasDBEnabled = true
	}

	if a.config.staticUsers == nil && hasDBEnabled == false {
		return nil, errs.Unauthenticated(ctx)
	}

	// 优先本地静态用户验证
	u, ok := a.config.staticUsers.Valid(req.Username, req.PasswordHash)
	if ok {
		tk, err := u.GetAccessToken(expiresIn, "")
		if err != nil {
			return nil, errs.Unauthenticated(ctx).WithMessage(err.Error())
		}

		accessToken = tk
	} else {
		// 尝试数据库验证
		// 根据不同的 provider_name 选择个性处理方式
		su, err := newSocialUsers(ctx, a.logger, a.config.aesKey, db, "local")
		if err != nil {
			return nil, err
		}

		tk, ok, err := su.PasswordCheck(ctx, req.Username, req.PasswordHash)
		if err != nil {
			return nil, errs.Unauthenticated(ctx).WithMessage(err.Error())
		}
		if !ok {
			return nil, errs.Unauthenticated(ctx)
		}

		accessToken = tk
	}

	result.AccessToken = accessToken
	result.ExpiresIn = expiresIn

	return result, nil
}

// CreateAuthToken 创建认证令牌
func (a *KnownAdminAPI) CreateAuthToken(ctx context.Context, req *adminv1.CreateAuthTokenRequest) (*adminv1.AuthToken, error) {
	result := &adminv1.AuthToken{TokenType: "Bearer"}

	appid := req.Appid
	if appid == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("create token must with appid")
	}

	// TODO; 当前先支持静态用户登录
	if a.config.staticUsers == nil {
		return nil, errs.Unauthenticated(ctx)
	}

	if req.Username == "" {
		return nil, errs.Unauthenticated(ctx)
	}

	u, ok := a.config.staticUsers.Valid(req.Username, req.PasswordHash)
	if !ok {
		return nil, errs.Unauthenticated(ctx)
	}

	expiresIn := req.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 24 * 60 * 60
	}

	tk, err := u.GetAccessToken(expiresIn, appid)
	if err != nil {
		return nil, errs.Unauthenticated(ctx).WithMessage(err.Error())
	}

	result.AccessToken = tk
	result.ExpiresIn = expiresIn

	return result, nil
}

// ListAuthProviders 获取认证提供列表
func (a *KnownAdminAPI) ListAuthProviders(ctx context.Context, req *adminv1.ListAuthProvidersRequest) (*adminv1.ListAuthProvidersResponse, error) {
	result := &adminv1.ListAuthProvidersResponse{
		Providers: make([]*adminv1.AuthProvider, 0),
	}

	db, err := a.GetLionClient()
	if err != nil {
		if a.config.staticUsers == nil || a.config.staticUsers.Len() == 0 {
			return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
		}

		// 支持本地登录
		result.Providers = append(result.Providers, &adminv1.AuthProvider{
			Code:   "local",
			Type:   adminv1.AuthProvider_LOCAL,
			Status: adminv1.AuthProvider_ACTIVE,
		})

		return result, nil
	}

	selectFields := []string{
		authproviders.FieldID,
		authproviders.FieldCode,
		authproviders.FieldProviderType,
		authproviders.FieldProviderStatus,
		authproviders.FieldDisplayName,
		authproviders.FieldDescription,
		authproviders.FieldSortOrder,
		authproviders.FieldIconURL,
		authproviders.FieldConfig,
		authproviders.FieldCreatedAt,
		authproviders.FieldUpdatedAt,
		// 注意：List 默认不查 SecretEncrypted（敏感字段）
	}

	// 构建过滤条件
	where := make([]predicate.AuthProviders, 0)

	// filter: 简单 AIP-160 风格解析
	if req.GetFilter() != "" {
		filterPredicates, err := parseListAuthProvidersFilter(req.GetFilter())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid filter: %v", err))
		}
		where = append(where, filterPredicates...)
	}

	// 默认排除已软删除的记录
	if !strings.Contains(req.GetFilter(), "deleted_at") && !strings.Contains(req.GetFilter(), "show_deleted") {
		where = append(where, authproviders.DeletedAtIsNil())
	}

	query := db.AuthProviders.Query().Where(where...)

	// 排序: 默认按 sort_order asc, id asc
	if req.GetOrderBy() != "" {
		switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
		case "sort_order asc":
			query = query.Order(lion.Asc(authproviders.FieldSortOrder), lion.Asc(authproviders.FieldID))
		case "sort_order desc":
			query = query.Order(lion.Desc(authproviders.FieldSortOrder), lion.Asc(authproviders.FieldID))
		case "created_at desc", "create_time desc":
			query = query.Order(lion.Desc(authproviders.FieldCreatedAt))
		case "created_at asc", "create_time asc":
			query = query.Order(lion.Asc(authproviders.FieldCreatedAt))
		case "id asc":
			query = query.Order(lion.Asc(authproviders.FieldID))
		case "id desc":
			query = query.Order(lion.Desc(authproviders.FieldID))
		default:
			query = query.Order(lion.Asc(authproviders.FieldSortOrder), lion.Asc(authproviders.FieldID))
		}
	} else {
		query = query.Order(lion.Asc(authproviders.FieldSortOrder), lion.Asc(authproviders.FieldID))
	}

	// 计算总数（分页前，不能带 Select，否则 COUNT 会包含多列导致 PG 报错）
	totalSize, err := query.Clone().Count(ctx)
	if err != nil {
		return nil, err
	}
	result.TotalSize = int32(totalSize)

	// 分页
	pageSize := GetPageSize(ctx, req.GetPageSize())

	// cursor-based 分页
	if req.GetPageToken() != "" {
		data, err := base64.StdEncoding.DecodeString(req.GetPageToken())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token: %v", err))
		}
		var lastID int
		if err := json.Unmarshal(data, &lastID); err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid page_token format: %v", err))
		}
		if lastID > 0 {
			query = query.Where(authproviders.IDGT(lastID))
		}
	}

	// offset-based 分页
	switch p := req.GetPagination().(type) {
	case *adminv1.ListAuthProvidersRequest_Offset:
		query = query.Offset(int(p.Offset))
	case *adminv1.ListAuthProvidersRequest_PageToken:
		// cursor 已在上面处理
	}

	// 应用 Select 限定返回字段（在 Count 之后，避免 COUNT 多列报错）并执行查询
	rows, err := query.Limit(int(pageSize)).Select(selectFields...).All(ctx)
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		p, err := dbToProtoAuthProvider(row, a.config.aesKey, false)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage(err.Error())
		}
		result.Providers = append(result.Providers, p)
	}

	// cursor 分页时生成 next_page_token
	if _, ok := req.GetPagination().(*adminv1.ListAuthProvidersRequest_PageToken); ok && len(rows) == int(pageSize) && len(rows) > 0 {
		last := rows[len(rows)-1].ID
		tokenData, _ := json.Marshal(last)
		result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
	}

	return result, nil
}

// parseListAuthProvidersFilter 解析 filter 字符串为 predicate 列表
// 支持 key=value 与 AND 组合
// 示例: "type=OIDC AND status=ACTIVE"、"type=3 AND code=github"
func parseListAuthProvidersFilter(filter string) ([]predicate.AuthProviders, error) {
	out := make([]predicate.AuthProviders, 0)
	parts := strings.Split(filter, " AND ")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		idx := strings.Index(p, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(strings.Trim(p[:idx], "\""))
		val := strings.TrimSpace(strings.Trim(p[idx+1:], "\""))

		switch key {
		case "type", "provider_type":
			// 支持枚举名或数字
			n, err := strconv.Atoi(val)
			if err != nil {
				// 尝试按枚举名解析
				enumVal, ok := adminv1.AuthProvider_Type_value[strings.ToUpper(val)]
				if !ok {
					return nil, fmt.Errorf("unknown provider type: %s", val)
				}
				n = int(enumVal)
			}
			out = append(out, authproviders.ProviderTypeEQ(n))
		case "status", "provider_status":
			// 支持枚举名或数字
			n, err := strconv.Atoi(val)
			if err != nil {
				enumVal, ok := adminv1.AuthProvider_Status_value[strings.ToUpper(val)]
				if !ok {
					return nil, fmt.Errorf("unknown provider status: %s", val)
				}
				n = int(enumVal)
			}
			out = append(out, authproviders.ProviderStatusEQ(n))
		case "code":
			out = append(out, authproviders.CodeContainsFold(val))
		case "display_name":
			out = append(out, authproviders.DisplayNameContainsFold(val))
		}
	}
	return out, nil
}

// UpsertAuthProviders 更新认证提供方列表
func (a *KnownAdminAPI) UpsertAuthProviders(ctx context.Context, req *adminv1.UpsertAuthProvidersRequest) (*adminv1.UpsertAuthProvidersResponse, error) {
	result := &adminv1.UpsertAuthProvidersResponse{}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	for _, p := range req.Providers {
		name := p.Code
		existID, err := db.AuthProviders.Query().Where(authproviders.CodeEQ(name)).OnlyID(ctx)
		if err != nil && !lion.IsNotFound(err) {
			return nil, err
		}

		configJSON, secretEnc, err := protoToDBConfig(p, a.config.aesKey)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage(err.Error())
		}

		if existID == 0 {
			create := db.AuthProviders.Create().
				SetCode(name).
				SetProviderType(int(p.GetType())).
				SetProviderStatus(int(p.Status.Number())).
				SetDisplayName(p.DisplayName).
				SetDescription(p.Description).
				SetSortOrder(int(p.SortOrder)).
				SetIconURL(p.IconUrl)

			if configJSON != nil {
				create.SetConfig(configJSON)
			}
			if len(secretEnc) > 0 {
				create.SetSecretEncrypted(secretEnc)
			}

			_, err = create.Save(ctx)
		} else {
			update := db.AuthProviders.Update().Where(authproviders.CodeEQ(name)).
				SetProviderStatus(int(p.Status.Number()))

			if p.DisplayName != "" {
				update.SetDisplayName(p.DisplayName)
			}
			if p.Description != "" {
				update.SetDescription(p.Description)
			}
			if p.SortOrder > 0 {
				update.SetSortOrder(int(p.SortOrder))
			}
			if p.IconUrl != "" {
				update.SetIconURL(p.IconUrl)
			}
			if configJSON != nil {
				update.SetConfig(configJSON)
			}
			if len(secretEnc) > 0 {
				update.SetSecretEncrypted(secretEnc)
			}

			err = update.Exec(ctx)
		}

		if err != nil {
			return nil, err
		}
	}

	return result, nil
}

// CreateAuthProvider 创建认证提供方
func (a *KnownAdminAPI) CreateAuthProvider(ctx context.Context, req *adminv1.CreateAuthProviderRequest) (*adminv1.AuthProvider, error) {
	if req.Provider == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body provider is nil")
	}

	code, err := schema.EnsureCode(req.Provider.Code)
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	req.Provider.Code = code

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	configJSON, secretEnc, err := protoToDBConfig(req.Provider, a.config.aesKey)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage(err.Error())
	}

	// TODO; 权限验证
	create := db.AuthProviders.Create().
		SetCode(req.Provider.Code).
		SetProviderType(int(req.Provider.Type.Number())).
		SetProviderStatus(int(req.Provider.Status.Number())).
		SetDisplayName(req.Provider.DisplayName).
		SetDescription(req.Provider.Description).
		SetSortOrder(int(req.Provider.SortOrder)).
		SetIconURL(req.Provider.IconUrl)

	if configJSON != nil {
		create.SetConfig(configJSON)
	}
	if len(secretEnc) > 0 {
		create.SetSecretEncrypted(secretEnc)
	}

	x, err := create.Save(ctx)
	if err != nil {
		return nil, err
	}

	result, err := dbToProtoAuthProvider(x, a.config.aesKey, false)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage(err.Error())
	}

	return result, nil
}

// GetAuthProvider 获取认证提供方
func (a *KnownAdminAPI) GetAuthProvider(ctx context.Context, req *adminv1.GetAuthProviderRequest) (*adminv1.AuthProvider, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("provider id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 查询认证提供方
	provider, err := db.AuthProviders.Get(ctx, int(req.Id))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("auth provider not found")
		}
		return nil, err
	}

	// Get 返回完整信息（包含解密后的敏感字段）
	result, err := dbToProtoAuthProvider(provider, a.config.aesKey, true)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage(err.Error())
	}

	return result, nil
}

// DeleteAuthProvider 删除认证提供方
func (a *KnownAdminAPI) DeleteAuthProvider(ctx context.Context, req *adminv1.DeleteAuthProviderRequest) (*emptypb.Empty, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("provider id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 检查认证提供方是否存在
	_, err = db.AuthProviders.Get(ctx, int(req.Id))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("auth provider not found")
		}
		return nil, err
	}

	// 执行删除
	err = db.AuthProviders.DeleteOneID(int(req.Id)).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// UpdateAuthProvider 更新认证提供方
func (a *KnownAdminAPI) UpdateAuthProvider(ctx context.Context, req *adminv1.UpdateAuthProviderRequest) (*adminv1.AuthProvider, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("provider id is required")
	}

	if req.Provider == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body provider is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 查找要更新的认证提供方
	provider, err := db.AuthProviders.Get(ctx, int(req.Id))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("auth provider not found")
		}
		return nil, err
	}

	// 构建更新操作
	update := provider.Update()

	// 更新公共字段
	if req.Provider.Code != "" {
		update.SetCode(req.Provider.Code)
	}
	if req.Provider.Type != adminv1.AuthProvider_TYPE_UNSPECIFIED {
		update.SetProviderType(int(req.Provider.Type.Number()))
	}
	update.SetProviderStatus(int(req.Provider.Status.Number()))
	if req.Provider.DisplayName != "" {
		update.SetDisplayName(req.Provider.DisplayName)
	}
	if req.Provider.Description != "" {
		update.SetDescription(req.Provider.Description)
	}
	if req.Provider.SortOrder > 0 {
		update.SetSortOrder(int(req.Provider.SortOrder))
	}
	if req.Provider.IconUrl != "" {
		update.SetIconURL(req.Provider.IconUrl)
	}

	// 更新类型特有配置和敏感凭证
	if req.Provider.GetConfig() != nil {
		configJSON, secretEnc, err := protoToDBConfig(req.Provider, a.config.aesKey)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage(err.Error())
		}
		if configJSON != nil {
			update.SetConfig(configJSON)
		}
		if len(secretEnc) > 0 {
			update.SetSecretEncrypted(secretEnc)
		}
	}

	// 执行更新
	updatedProvider, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}

	// 返回更新后的完整信息
	result, err := dbToProtoAuthProvider(updatedProvider, a.config.aesKey, true)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage(err.Error())
	}

	return result, nil
}
