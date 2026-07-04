package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/oauth2clients"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/schema"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// generateClientSecret 生成 32 字节随机密钥并返回 base64 编码字符串
func generateClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate client secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// oauth2ClientToProto 将 ent 行转换为 proto message
// 注意：永不映射 client_secret_hash
func oauth2ClientToProto(row *lion.OAuth2Clients) *adminv1.OAuth2Client {
	var deletedAt *timestamppb.Timestamp
	if row.DeletedAt != nil {
		deletedAt = timestamppb.New(*row.DeletedAt)
	}

	return &adminv1.OAuth2Client{
		Id:           int64(row.ID),
		ClientId:     row.ClientID,
		ClientStatus: adminv1.OAuth2Client_ClientStatus(row.ClientStatus),
		DisplayName:  row.DisplayName,
		Description:  row.Description,
		LogoUrl:      row.LogoURL,
		RedirectUris: row.RedirectUris,
		GrantTypes:   row.GrantTypes,
		Scopes:       row.Scopes,
		CreatedBy:    row.CreatedBy,
		UpdatedBy:    row.UpdatedBy,
		CreatedAt:    timestamppb.New(row.CreatedAt),
		UpdatedAt:    timestamppb.New(row.UpdatedAt),
		DeletedAt:    deletedAt,
	}
}

// ListOAuth2Clients 查询 OAuth2 客户端列表
func (a *KnownAdminAPI) ListOAuth2Clients(ctx context.Context, req *adminv1.ListOAuth2ClientsRequest) (*adminv1.ListOAuth2ClientsResponse, error) {
	result := &adminv1.ListOAuth2ClientsResponse{
		Clients: make([]*adminv1.OAuth2Client, 0),
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	selectFields := []string{
		oauth2clients.FieldID,
		oauth2clients.FieldClientID,
		oauth2clients.FieldDisplayName,
		oauth2clients.FieldClientStatus,
		oauth2clients.FieldRedirectUris,
		oauth2clients.FieldGrantTypes,
		oauth2clients.FieldScopes,
		oauth2clients.FieldLogoURL,
		oauth2clients.FieldDescription,
		oauth2clients.FieldCreatedAt,
		oauth2clients.FieldUpdatedAt,
		oauth2clients.FieldCreatedBy,
		oauth2clients.FieldUpdatedBy,
		oauth2clients.FieldDeletedAt,
		// 注意：List 永不查 ClientSecretHash（敏感字段）
	}

	// 构建过滤条件
	where := make([]predicate.OAuth2Clients, 0)

	// filter: 简单 AIP-160 风格解析
	if req.GetFilter() != "" {
		filterPredicates, err := parseListOAuth2ClientsFilter(req.GetFilter())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid filter: %v", err))
		}
		where = append(where, filterPredicates...)
	}

	// client_status: 独立快捷过滤参数
	if req.GetClientStatus() > 0 {
		where = append(where, oauth2clients.ClientStatusEQ(int(req.GetClientStatus())))
	}

	// 默认排除已软删除的记录
	if !strings.Contains(req.GetFilter(), "deleted_at") && !strings.Contains(req.GetFilter(), "show_deleted") {
		where = append(where, oauth2clients.DeletedAtIsNil())
	}

	query := db.OAuth2Clients.Query().Where(where...)

	// 排序: 默认按 client_status asc, id asc
	if req.GetOrderBy() != "" {
		switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
		case "client_status asc":
			query = query.Order(lion.Asc(oauth2clients.FieldClientStatus), lion.Asc(oauth2clients.FieldID))
		case "client_status desc":
			query = query.Order(lion.Desc(oauth2clients.FieldClientStatus), lion.Asc(oauth2clients.FieldID))
		case "created_at desc", "create_time desc":
			query = query.Order(lion.Desc(oauth2clients.FieldCreatedAt))
		case "created_at asc", "create_time asc":
			query = query.Order(lion.Asc(oauth2clients.FieldCreatedAt))
		case "id asc":
			query = query.Order(lion.Asc(oauth2clients.FieldID))
		case "id desc":
			query = query.Order(lion.Desc(oauth2clients.FieldID))
		case "display_name asc":
			query = query.Order(lion.Asc(oauth2clients.FieldDisplayName))
		case "display_name desc":
			query = query.Order(lion.Desc(oauth2clients.FieldDisplayName))
		default:
			query = query.Order(lion.Asc(oauth2clients.FieldClientStatus), lion.Asc(oauth2clients.FieldID))
		}
	} else {
		query = query.Order(lion.Asc(oauth2clients.FieldClientStatus), lion.Asc(oauth2clients.FieldID))
	}

	// 计算总数
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
			query = query.Where(oauth2clients.IDGT(lastID))
		}
	}

	// offset-based 分页
	switch p := req.GetPagination().(type) {
	case *adminv1.ListOAuth2ClientsRequest_Offset:
		query = query.Offset(int(p.Offset))
	case *adminv1.ListOAuth2ClientsRequest_PageToken:
		// cursor 已在上面处理
	}

	// 应用 Select 限定返回字段并执行查询
	rows, err := query.Limit(int(pageSize)).Select(selectFields...).All(ctx)
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		result.Clients = append(result.Clients, oauth2ClientToProto(row))
	}

	// cursor 分页时生成 next_page_token
	if _, ok := req.GetPagination().(*adminv1.ListOAuth2ClientsRequest_PageToken); ok && len(rows) == int(pageSize) && len(rows) > 0 {
		last := rows[len(rows)-1].ID
		tokenData, _ := json.Marshal(last)
		result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
	}

	return result, nil
}

// parseListOAuth2ClientsFilter 解析 filter 字符串为 predicate 列表
// 支持 key=value 与 AND 组合
// 示例: "client_status=ACTIVE AND display_name~="web""
func parseListOAuth2ClientsFilter(filter string) ([]predicate.OAuth2Clients, error) {
	out := make([]predicate.OAuth2Clients, 0)
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
		case "client_status":
			n, err := strconv.Atoi(val)
			if err != nil {
				enumVal, ok := adminv1.OAuth2Client_ClientStatus_value[strings.ToUpper(val)]
				if !ok {
					return nil, fmt.Errorf("unknown client status: %s", val)
				}
				n = int(enumVal)
			}
			out = append(out, oauth2clients.ClientStatusEQ(n))
		case "client_id":
			out = append(out, oauth2clients.ClientIDEqualFold(val))
		case "display_name":
			out = append(out, oauth2clients.DisplayNameContainsFold(val))
		}
	}
	return out, nil
}

// CreateOAuth2Client 创建 OAuth2 客户端
func (a *KnownAdminAPI) CreateOAuth2Client(ctx context.Context, req *adminv1.CreateOAuth2ClientRequest) (*adminv1.CreateOAuth2ClientResponse, error) {
	if req.Client == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body client is nil")
	}

	// 生成或校验 client_id
	clientID, err := schema.EnsureCode(req.Client.ClientId)
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	req.Client.ClientId = clientID

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 唯一性校验：client_id 重复检查
	exists, err := db.OAuth2Clients.Query().
		Where(oauth2clients.ClientIDEQ(clientID), oauth2clients.DeletedAtIsNil()).
		Count(ctx)
	if err != nil {
		return nil, err
	}
	if exists > 0 {
		return nil, errs.AlreadyExists(ctx).WithMessage(fmt.Sprintf("oauth2 client with client_id %q already exists", clientID))
	}

	// 处理 client_secret
	plaintextSecret := req.GetClientSecret()
	returnSecret := ""
	if plaintextSecret == "" {
		// 未提供则自动生成
		plaintextSecret, err = generateClientSecret()
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage(err.Error())
		}
		returnSecret = plaintextSecret
	}

	// bcrypt 哈希存储
	secretHash, err := crypto.BcryptHash(plaintextSecret)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage(fmt.Sprintf("bcrypt hash failed: %v", err))
	}

	// 默认状态为 ACTIVE
	clientStatus := int(req.Client.ClientStatus.Number())
	if clientStatus == 0 {
		clientStatus = int(adminv1.OAuth2Client_ACTIVE.Number())
	}

	create := db.OAuth2Clients.Create().
		SetClientID(clientID).
		SetClientSecretHash(secretHash).
		SetDisplayName(req.Client.DisplayName).
		SetClientStatus(clientStatus).
		SetRedirectUris(req.Client.RedirectUris).
		SetGrantTypes(req.Client.GrantTypes).
		SetScopes(req.Client.Scopes).
		SetLogoURL(req.Client.LogoUrl).
		SetDescription(req.Client.Description)

	// 设置审计字段
	if actor, err := GetUserID(ctx); err == nil && actor != 0 {
		create.SetCreatedBy(actor).SetUpdatedBy(actor)
	}

	row, err := create.Save(ctx)
	if err != nil {
		return nil, err
	}

	return &adminv1.CreateOAuth2ClientResponse{
		Client:       oauth2ClientToProto(row),
		ClientSecret: returnSecret,
	}, nil
}

// GetOAuth2Client 获取 OAuth2 客户端详情
func (a *KnownAdminAPI) GetOAuth2Client(ctx context.Context, req *adminv1.GetOAuth2ClientRequest) (*adminv1.OAuth2Client, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("client id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	row, err := db.OAuth2Clients.Get(ctx, int(req.Id))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("oauth2 client not found")
		}
		return nil, err
	}

	return oauth2ClientToProto(row), nil
}

// UpdateOAuth2Client 更新 OAuth2 客户端
func (a *KnownAdminAPI) UpdateOAuth2Client(ctx context.Context, req *adminv1.UpdateOAuth2ClientRequest) (*adminv1.OAuth2Client, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("client id is required")
	}

	if req.Client == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body client is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 查找要更新的客户端
	row, err := db.OAuth2Clients.Get(ctx, int(req.Id))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("oauth2 client not found")
		}
		return nil, err
	}

	update := row.Update()

	// 设置审计字段
	if actor, err := GetUserID(ctx); err == nil && actor != 0 {
		update.SetUpdatedBy(actor)
	}

	// 根据 update_mask 更新字段（client_id 不可修改）
	mask := req.GetUpdateMask()
	if mask != nil && len(mask.GetPaths()) > 0 {
		for _, path := range mask.GetPaths() {
			switch path {
			case "display_name":
				update.SetDisplayName(req.Client.DisplayName)
			case "client_status":
				update.SetClientStatus(int(req.Client.ClientStatus.Number()))
			case "redirect_uris":
				update.SetRedirectUris(req.Client.RedirectUris)
			case "grant_types":
				update.SetGrantTypes(req.Client.GrantTypes)
			case "scopes":
				update.SetScopes(req.Client.Scopes)
			case "logo_url":
				update.SetLogoURL(req.Client.LogoUrl)
			case "description":
				update.SetDescription(req.Client.Description)
			case "client_id":
				// client_id 不可修改，忽略
			}
		}
	} else {
		// 未提供 update_mask，更新所有非空字段
		if req.Client.DisplayName != "" {
			update.SetDisplayName(req.Client.DisplayName)
		}
		if req.Client.ClientStatus != adminv1.OAuth2Client_CLIENT_STATUS_UNSPECIFIED {
			update.SetClientStatus(int(req.Client.ClientStatus.Number()))
		}
		if req.Client.RedirectUris != nil {
			update.SetRedirectUris(req.Client.RedirectUris)
		}
		if req.Client.GrantTypes != nil {
			update.SetGrantTypes(req.Client.GrantTypes)
		}
		if req.Client.Scopes != nil {
			update.SetScopes(req.Client.Scopes)
		}
		if req.Client.LogoUrl != "" {
			update.SetLogoURL(req.Client.LogoUrl)
		}
		if req.Client.Description != "" {
			update.SetDescription(req.Client.Description)
		}
	}

	// client_secret 轮换
	if req.GetClientSecret() != "" {
		secretHash, err := crypto.BcryptHash(req.GetClientSecret())
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage(fmt.Sprintf("bcrypt hash failed: %v", err))
		}
		update.SetClientSecretHash(secretHash)
	}

	updated, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}

	return oauth2ClientToProto(updated), nil
}

// DeleteOAuth2Client 删除 OAuth2 客户端（软删除）
func (a *KnownAdminAPI) DeleteOAuth2Client(ctx context.Context, req *adminv1.DeleteOAuth2ClientRequest) (*emptypb.Empty, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("client id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 检查客户端是否存在
	_, err = db.OAuth2Clients.Get(ctx, int(req.Id))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("oauth2 client not found")
		}
		return nil, err
	}

	// 执行软删除
	err = db.OAuth2Clients.DeleteOneID(int(req.Id)).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}
