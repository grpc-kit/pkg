package admin

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"strings"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
	"github.com/grpc-kit/pkg/lion/credentials"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/schema"
	"github.com/grpc-kit/pkg/lion/useridentities"
	"github.com/grpc-kit/pkg/lion/users"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// credentialToProto 将 ent 行转换为 proto message。
// 永不映射 *_encrypted 敏感字段；key_material oneof 仅返回非敏感数据。
func credentialToProto(row *lion.Credentials) *adminv1.Credential {
	result := &adminv1.Credential{
		Id:          int64(row.ID),
		Code:        row.Code,
		DisplayName: row.DisplayName,
		Description: row.Description,
		Type:        adminv1.Credential_Type(row.CredentialType),
		Algorithm:   adminv1.Credential_Algorithm(row.CredentialAlgorithm),
		Usage:       adminv1.Credential_Usage(row.CredentialUsage),
		Visibility:  adminv1.Visibility(row.CredentialVisibility),
		Status:      adminv1.Credential_Status(row.CredentialStatus),
		Source:      adminv1.Credential_Source(row.CredentialSource),
		Protected:   row.Protected,
		KeyId:       row.KeyID,
		CreatedBy:   row.CreatedBy,
		UpdatedBy:   row.UpdatedBy,
		CreatedAt:   timestamppb.New(row.CreatedAt),
		UpdatedAt:   timestamppb.New(row.UpdatedAt),
	}

	if row.DeletedAt != nil {
		result.DeletedAt = timestamppb.New(*row.DeletedAt)
	}

	if row.NotBefore != nil {
		result.NotBefore = timestamppb.New(*row.NotBefore)
	}

	if row.ExpiresAt != nil {
		result.ExpiresAt = timestamppb.New(*row.ExpiresAt)
	}

	if row.Metadata != nil {
		result.Metadata = make(map[string]string, len(row.Metadata))
		for k, v := range row.Metadata {
			result.Metadata[k] = v
		}
	}

	// key_material oneof: 仅返回非敏感数据
	switch row.CredentialType {
	case int(adminv1.Credential_API_KEY.Number()):
		result.KeyMaterial = &adminv1.Credential_ApiKey{
			ApiKey: &adminv1.Credential_ApiKeyData{
				ApiKey: row.APIKey,
				// ApiSecret 永不返回
			},
		}
	case int(adminv1.Credential_KEY_PAIR.Number()):
		result.KeyMaterial = &adminv1.Credential_KeyPair{
			KeyPair: &adminv1.Credential_KeyPairData{
				PublicKey: row.PublicKey,
				// PrivateKey / Passphrase 永不返回
			},
		}
	case int(adminv1.Credential_X509.Number()):
		result.KeyMaterial = &adminv1.Credential_X509Data_{
			X509Data: &adminv1.Credential_X509Data{
				Certificate: row.Certificate,
				CaChain:     row.CaChain,
				// PrivateKey / Passphrase 永不返回
			},
		}
	case int(adminv1.Credential_LICENSE.Number()):
		result.KeyMaterial = &adminv1.Credential_License{
			License: &adminv1.Credential_LicenseData{
				Signature: row.Signature,
				// LicenseKey 永不返回
			},
		}
	case int(adminv1.Credential_SYMMETRIC_KEY.Number()), int(adminv1.Credential_SECRET.Number()):
		// SymmetricKey 永不返回（敏感数据），仅设置 oneof 类型标记
		// 返回空 []byte 表示该凭证为对称密钥/密文类型，但内容不暴露
	}
	// TYPE_UNSPECIFIED: 不设置 key_material

	return result
}

// generateCredentialCode 生成或校验凭证编码。
// 空 code 时自动生成，非空时校验合法性。使用 schema.EnsureCode 统一处理。
func generateCredentialCode(code string) (string, error) {
	return schema.EnsureCode(code)
}

// computeKeyID 根据凭证类型计算 key_id（SHA256 摘要前 11 个十六进制字符）
func computeKeyID(cred *adminv1.Credential) string {
	switch cred.GetType() {
	case adminv1.Credential_API_KEY:
		if ak := cred.GetApiKey(); ak != nil {
			return crypto.SHA256([]byte(ak.ApiKey))[:11]
		}
	case adminv1.Credential_SYMMETRIC_KEY:
		return crypto.SHA256(cred.GetSymmetricKey())[:11]
	case adminv1.Credential_KEY_PAIR:
		if kp := cred.GetKeyPair(); kp != nil {
			return crypto.SHA256(kp.PublicKey)[:11]
		}
	case adminv1.Credential_X509:
		if x := cred.GetX509Data(); x != nil {
			return crypto.SHA256(x.Certificate)[:11]
		}
	case adminv1.Credential_LICENSE:
		if lic := cred.GetLicense(); lic != nil {
			return crypto.SHA256(lic.LicenseKey)[:11]
		}
	case adminv1.Credential_SECRET:
		return crypto.SHA256(cred.GetSymmetricKey())[:11]
	}
	return ""
}

// isTokenPersistenceRequest 判断是否为 Token 持久化请求。
// 识别条件：type=SECRET + usage=AUTH + source=USER
// 用于决定是否执行 key_id 幂等检查。
func isTokenPersistenceRequest(cred *adminv1.Credential) bool {
	return cred.GetType() == adminv1.Credential_SECRET &&
		cred.GetUsage() == adminv1.Credential_AUTH &&
		cred.GetSource() == adminv1.Credential_USER
}

// encryptSensitiveField 使用 AES-GCM 加密敏感字段
func (a *KnownAdminAPI) encryptSensitiveField(plainText []byte) ([]byte, error) {
	if len(plainText) == 0 {
		return nil, nil
	}
	return crypto.EncryptAES(a.config.aesKey, plainText)
}

// decryptToken 使用 AES-GCM 解密持久化的 Token。
// 供后续 GetCredential 扩展、审计、Token 迁移等场景按需解密还原完整 token。
func (a *KnownAdminAPI) decryptToken(encryptedToken []byte) (string, error) {
	plain, err := crypto.DecryptAES(a.config.aesKey, encryptedToken)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// CreateCredential 创建凭证
func (a *KnownAdminAPI) CreateCredential(ctx context.Context, req *adminv1.CreateCredentialRequest) (*adminv1.Credential, error) {
	if req.Credential == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body credential is nil")
	}

	cred := req.Credential

	// 生成或校验 code
	code, err := generateCredentialCode(cred.Code)
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid code: %v", err))
	}
	cred.Code = code

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 唯一性校验：code 重复检查
	exists, err := db.Credentials.Query().
		Where(credentials.CodeEQ(code), credentials.DeletedAtIsNil()).
		Count(ctx)
	if err != nil {
		return nil, err
	}
	if exists > 0 {
		return nil, errs.AlreadyExists(ctx).WithMessage(fmt.Sprintf("credential with code %q already exists", code))
	}

	// 计算 key_id
	keyID := computeKeyID(cred)

	// Token 持久化幂等检查：若 key_id 已存在则返回已有记录，
	// 避免同一 token 被重复持久化。
	if isTokenPersistenceRequest(cred) && keyID != "" {
		existing, err := db.Credentials.Query().
			Where(credentials.KeyIDEQ(keyID), credentials.DeletedAtIsNil()).
			Only(ctx)
		if err == nil && existing != nil {
			return credentialToProto(existing), nil
		}
		if !lion.IsNotFound(err) {
			return nil, err
		}
		// NotFound -> 继续创建流程
	}

	create := db.Credentials.Create().
		SetCode(code).
		SetCredentialType(int(cred.Type.Number())).
		SetCredentialAlgorithm(int(cred.Algorithm.Number())).
		SetCredentialUsage(int(cred.Usage.Number())).
		SetCredentialVisibility(int(cred.Visibility.Number())).
		SetCredentialStatus(int(cred.Status.Number())).
		SetCredentialSource(int(cred.Source.Number())).
		SetDisplayName(cred.DisplayName).
		SetDescription(cred.Description).
		SetKeyID(keyID)

	// 设置审计字段
	if actor, err := GetUserID(ctx); err == nil && actor != 0 {
		create.SetCreatedBy(actor).SetUpdatedBy(actor)
	}

	// 设置生命周期
	if cred.NotBefore != nil {
		create.SetNillableNotBefore(timePtr(cred.NotBefore.AsTime()))
	}
	if cred.ExpiresAt != nil {
		create.SetNillableExpiresAt(timePtr(cred.ExpiresAt.AsTime()))
	}

	// 设置 metadata
	if cred.Metadata != nil {
		create.SetMetadata(cred.Metadata)
	}

	// 根据类型设置密钥材料
	switch cred.Type {
	case adminv1.Credential_API_KEY:
		ak := cred.GetApiKey()
		if ak == nil {
			return nil, errs.InvalidArgument(ctx).WithMessage("api_key data is required for API_KEY type")
		}
		create.SetAPIKey(ak.ApiKey)
		if len(ak.ApiSecret) > 0 {
			enc, err := a.encryptSensitiveField(ak.ApiSecret)
			if err != nil {
				return nil, errs.Internal(ctx).WithMessage(fmt.Sprintf("encrypt api_secret failed: %v", err))
			}
			create.SetAPISecretEncrypted(enc)
		}

	case adminv1.Credential_SYMMETRIC_KEY, adminv1.Credential_SECRET:
		symKey := cred.GetSymmetricKey()
		if len(symKey) == 0 {
			return nil, errs.InvalidArgument(ctx).WithMessage("symmetric_key is required for SYMMETRIC_KEY/SECRET type")
		}
		enc, err := a.encryptSensitiveField(symKey)
		if err != nil {
			return nil, errs.Internal(ctx).WithMessage(fmt.Sprintf("encrypt symmetric_key failed: %v", err))
		}
		create.SetSymmetricKeyEncrypted(enc)

	case adminv1.Credential_KEY_PAIR:
		kp := cred.GetKeyPair()
		if kp == nil {
			return nil, errs.InvalidArgument(ctx).WithMessage("key_pair data is required for KEY_PAIR type")
		}
		create.SetPublicKey(kp.PublicKey)
		if len(kp.PrivateKey) > 0 {
			enc, err := a.encryptSensitiveField(kp.PrivateKey)
			if err != nil {
				return nil, errs.Internal(ctx).WithMessage(fmt.Sprintf("encrypt private_key failed: %v", err))
			}
			create.SetPrivateKeyEncrypted(enc)
		}
		if len(kp.Passphrase) > 0 {
			enc, err := a.encryptSensitiveField(kp.Passphrase)
			if err != nil {
				return nil, errs.Internal(ctx).WithMessage(fmt.Sprintf("encrypt passphrase failed: %v", err))
			}
			create.SetPassphraseEncrypted(enc)
		}

	case adminv1.Credential_X509:
		x := cred.GetX509Data()
		if x == nil {
			return nil, errs.InvalidArgument(ctx).WithMessage("x509_data is required for X509 type")
		}
		create.SetCertificate(x.Certificate)
		if len(x.CaChain) > 0 {
			create.SetCaChain(x.CaChain)
		}
		if len(x.PrivateKey) > 0 {
			enc, err := a.encryptSensitiveField(x.PrivateKey)
			if err != nil {
				return nil, errs.Internal(ctx).WithMessage(fmt.Sprintf("encrypt private_key failed: %v", err))
			}
			create.SetPrivateKeyEncrypted(enc)
		}
		if len(x.Passphrase) > 0 {
			enc, err := a.encryptSensitiveField(x.Passphrase)
			if err != nil {
				return nil, errs.Internal(ctx).WithMessage(fmt.Sprintf("encrypt passphrase failed: %v", err))
			}
			create.SetPassphraseEncrypted(enc)
		}

	case adminv1.Credential_LICENSE:
		lic := cred.GetLicense()
		if lic == nil {
			return nil, errs.InvalidArgument(ctx).WithMessage("license data is required for LICENSE type")
		}
		if len(lic.LicenseKey) > 0 {
			enc, err := a.encryptSensitiveField(lic.LicenseKey)
			if err != nil {
				return nil, errs.Internal(ctx).WithMessage(fmt.Sprintf("encrypt license_key failed: %v", err))
			}
			create.SetLicenseKeyEncrypted(enc)
		}
		if len(lic.Signature) > 0 {
			create.SetSignature(lic.Signature)
		}

	default:
		return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("unsupported credential type: %s", cred.Type))
	}

	row, err := create.Save(ctx)
	if err != nil {
		return nil, err
	}

	return credentialToProto(row), nil
}

// ListCredentials 查询凭证列表
func (a *KnownAdminAPI) ListCredentials(ctx context.Context, req *adminv1.ListCredentialsRequest) (*adminv1.ListCredentialsResponse, error) {
	result := &adminv1.ListCredentialsResponse{
		Credentials: make([]*adminv1.Credential, 0),
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// selectFields: 排除所有 *_encrypted 敏感字段
	selectFields := []string{
		credentials.FieldID,
		credentials.FieldCode,
		credentials.FieldDisplayName,
		credentials.FieldDescription,
		credentials.FieldCredentialType,
		credentials.FieldCredentialAlgorithm,
		credentials.FieldCredentialUsage,
		credentials.FieldCredentialVisibility,
		credentials.FieldCredentialStatus,
		credentials.FieldCredentialSource,
		credentials.FieldProtected,
		credentials.FieldKeyID,
		credentials.FieldAPIKey,
		credentials.FieldPublicKey,
		credentials.FieldCertificate,
		credentials.FieldCaChain,
		credentials.FieldSignature,
		credentials.FieldNotBefore,
		credentials.FieldExpiresAt,
		credentials.FieldMetadata,
		credentials.FieldCreatedBy,
		credentials.FieldUpdatedBy,
		credentials.FieldCreatedAt,
		credentials.FieldUpdatedAt,
		credentials.FieldDeletedAt,
		// 注意：List 永不查 *_encrypted 字段
	}

	// 构建过滤条件
	where := make([]predicate.Credentials, 0)

	// filter: 简单 AIP-160 风格解析
	if req.GetFilter() != "" {
		filterPredicates, err := parseListCredentialsFilter(req.GetFilter())
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("invalid filter: %v", err))
		}
		where = append(where, filterPredicates...)
	}

	// 快捷过滤参数
	if req.GetCredentialType() > 0 {
		where = append(where, credentials.CredentialTypeEQ(int(req.GetCredentialType())))
	}
	if req.GetCredentialStatus() > 0 {
		where = append(where, credentials.CredentialStatusEQ(int(req.GetCredentialStatus())))
	}
	if req.GetCredentialUsage() > 0 {
		where = append(where, credentials.CredentialUsageEQ(int(req.GetCredentialUsage())))
	}

	// 默认排除已软删除的记录
	if !strings.Contains(req.GetFilter(), "deleted_at") && !strings.Contains(req.GetFilter(), "show_deleted") {
		where = append(where, credentials.DeletedAtIsNil())
	}

	query := db.Credentials.Query().Where(where...)

	// 排序
	if req.GetOrderBy() != "" {
		switch strings.TrimSpace(strings.ToLower(req.GetOrderBy())) {
		case "credential_status asc":
			query = query.Order(lion.Asc(credentials.FieldCredentialStatus), lion.Asc(credentials.FieldID))
		case "credential_status desc":
			query = query.Order(lion.Desc(credentials.FieldCredentialStatus), lion.Asc(credentials.FieldID))
		case "created_at desc", "create_time desc":
			query = query.Order(lion.Desc(credentials.FieldCreatedAt))
		case "created_at asc", "create_time asc":
			query = query.Order(lion.Asc(credentials.FieldCreatedAt))
		case "id asc":
			query = query.Order(lion.Asc(credentials.FieldID))
		case "id desc":
			query = query.Order(lion.Desc(credentials.FieldID))
		case "display_name asc":
			query = query.Order(lion.Asc(credentials.FieldDisplayName))
		case "display_name desc":
			query = query.Order(lion.Desc(credentials.FieldDisplayName))
		case "credential_type asc":
			query = query.Order(lion.Asc(credentials.FieldCredentialType), lion.Asc(credentials.FieldID))
		case "credential_type desc":
			query = query.Order(lion.Desc(credentials.FieldCredentialType), lion.Asc(credentials.FieldID))
		default:
			query = query.Order(lion.Asc(credentials.FieldCredentialStatus), lion.Asc(credentials.FieldID))
		}
	} else {
		query = query.Order(lion.Asc(credentials.FieldCredentialStatus), lion.Asc(credentials.FieldID))
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
			query = query.Where(credentials.IDGT(lastID))
		}
	}

	// offset-based 分页
	switch p := req.GetPagination().(type) {
	case *adminv1.ListCredentialsRequest_Offset:
		query = query.Offset(int(p.Offset))
	case *adminv1.ListCredentialsRequest_PageToken:
		// cursor 已在上面处理
	}

	// 应用 Select 限定返回字段并执行查询
	rows, err := query.Limit(int(pageSize)).Select(selectFields...).All(ctx)
	if err != nil {
		return nil, err
	}

	for _, row := range rows {
		result.Credentials = append(result.Credentials, credentialToProto(row))
	}

	// cursor 分页时生成 next_page_token
	if _, ok := req.GetPagination().(*adminv1.ListCredentialsRequest_PageToken); ok && len(rows) == int(pageSize) && len(rows) > 0 {
		last := rows[len(rows)-1].ID
		tokenData, _ := json.Marshal(last)
		result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
	}

	return result, nil
}

// parseListCredentialsFilter 解析 filter 字符串为 predicate 列表
// 支持 key=value 与 AND 组合
// 示例: "credential_status=ACTIVE AND credential_type=KEY_PAIR"
func parseListCredentialsFilter(filter string) ([]predicate.Credentials, error) {
	out := make([]predicate.Credentials, 0)
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
		case "credential_status":
			n, err := strconv.Atoi(val)
			if err != nil {
				enumVal, ok := adminv1.Credential_Status_value[strings.ToUpper(val)]
				if !ok {
					return nil, fmt.Errorf("unknown credential status: %s", val)
				}
				n = int(enumVal)
			}
			out = append(out, credentials.CredentialStatusEQ(n))
		case "credential_type":
			n, err := strconv.Atoi(val)
			if err != nil {
				enumVal, ok := adminv1.Credential_Type_value[strings.ToUpper(val)]
				if !ok {
					return nil, fmt.Errorf("unknown credential type: %s", val)
				}
				n = int(enumVal)
			}
			out = append(out, credentials.CredentialTypeEQ(n))
		case "credential_usage":
			n, err := strconv.Atoi(val)
			if err != nil {
				enumVal, ok := adminv1.Credential_Usage_value[strings.ToUpper(val)]
				if !ok {
					return nil, fmt.Errorf("unknown credential usage: %s", val)
				}
				n = int(enumVal)
			}
			out = append(out, credentials.CredentialUsageEQ(n))
		case "code":
			out = append(out, credentials.CodeEqualFold(val))
		case "display_name":
			out = append(out, credentials.DisplayNameContainsFold(val))
		case "key_id":
			out = append(out, credentials.KeyIDEQ(val))
		}
	}
	return out, nil
}

// GetCredential 获取凭证详情
func (a *KnownAdminAPI) GetCredential(ctx context.Context, req *adminv1.GetCredentialRequest) (*adminv1.Credential, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("credential id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	row, err := db.Credentials.Get(ctx, int(req.Id))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("credential not found")
		}
		return nil, err
	}

	return credentialToProto(row), nil
}

// UpdateCredential 更新凭证
// 仅允许更新 status / display_name / description / expires_at / metadata
// 受保护（protected=true）的凭证仅允许更新 display_name / description
func (a *KnownAdminAPI) UpdateCredential(ctx context.Context, req *adminv1.UpdateCredentialRequest) (*adminv1.Credential, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("credential id is required")
	}

	if req.Credential == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("request body credential is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 查找要更新的凭证
	row, err := db.Credentials.Get(ctx, int(req.Id))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("credential not found")
		}
		return nil, err
	}

	update := row.Update()

	// 设置审计字段
	if actor, err := GetUserID(ctx); err == nil && actor != 0 {
		update.SetUpdatedBy(actor)
	}

	cred := req.Credential
	isProtected := row.Protected

	// 根据 update_mask 更新字段
	mask := req.GetUpdateMask()
	if mask != nil && len(mask.GetPaths()) > 0 {
		for _, path := range mask.GetPaths() {
			// 受保护凭证仅允许更新 display_name / description
			if isProtected && path != "display_name" && path != "description" {
				continue
			}
			switch path {
			case "display_name":
				update.SetDisplayName(cred.DisplayName)
			case "description":
				update.SetDescription(cred.Description)
			case "status":
				update.SetCredentialStatus(int(cred.Status.Number()))
			case "expires_at":
				if cred.ExpiresAt != nil {
					update.SetNillableExpiresAt(timePtr(cred.ExpiresAt.AsTime()))
				}
			case "not_before":
				if cred.NotBefore != nil {
					update.SetNillableNotBefore(timePtr(cred.NotBefore.AsTime()))
				}
			case "metadata":
				if cred.Metadata != nil {
					update.SetMetadata(cred.Metadata)
				}
			case "code", "type", "algorithm", "key_id", "key_material":
				// 不可修改字段，忽略
			}
		}
	} else {
		// 未提供 update_mask，更新所有非空字段
		if cred.DisplayName != "" {
			update.SetDisplayName(cred.DisplayName)
		}
		if cred.Description != "" {
			update.SetDescription(cred.Description)
		}
		if !isProtected && cred.Status != adminv1.Credential_STATUS_UNSPECIFIED {
			update.SetCredentialStatus(int(cred.Status.Number()))
		}
		if !isProtected && cred.ExpiresAt != nil {
			update.SetNillableExpiresAt(timePtr(cred.ExpiresAt.AsTime()))
		}
		if !isProtected && cred.NotBefore != nil {
			update.SetNillableNotBefore(timePtr(cred.NotBefore.AsTime()))
		}
		if !isProtected && cred.Metadata != nil {
			update.SetMetadata(cred.Metadata)
		}
	}

	updated, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}

	return credentialToProto(updated), nil
}

// DeleteCredential 删除凭证（软删除）
// 受保护（protected=true）的凭证不可删除
func (a *KnownAdminAPI) DeleteCredential(ctx context.Context, req *adminv1.DeleteCredentialRequest) (*emptypb.Empty, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("credential id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 检查凭证是否存在
	row, err := db.Credentials.Get(ctx, int(req.Id))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("credential not found")
		}
		return nil, err
	}

	// 受保护凭证不可删除
	if row.Protected {
		return nil, errs.InvalidArgument(ctx).WithMessage("protected credential cannot be deleted")
	}

	// 执行软删除
	err = db.Credentials.DeleteOneID(int(req.Id)).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// verifyUserPassword 验证用户密码，支持静态用户和数据库注册用户。
// 优先尝试静态用户验证（SHA256 字符串比较），失败后尝试数据库用户验证（bcrypt 比较）。
// 返回 true 表示密码验证通过。
func (a *KnownAdminAPI) verifyUserPassword(ctx context.Context, username, passwordHash string) bool {
	// 1. 尝试静态用户验证
	if a.config.staticUsers != nil {
		if _, ok := a.config.staticUsers.Valid(username, passwordHash); ok {
			return true
		}
	}

	// 2. 尝试数据库用户验证
	db, err := a.GetLionClient()
	if err != nil {
		// 没有数据库且静态用户验证已失败
		return false
	}

	// 查询 LOCAL 类型的认证提供方及其关联的用户身份
	provider, err := db.AuthProviders.Query().
		Select(
			authproviders.FieldID,
		).
		Where(authproviders.ProviderTypeEQ(int(adminv1.AuthProvider_LOCAL.Number()))).
		Only(ctx)
	if err != nil {
		return false
	}

	// 查询用户及其身份信息
	u, err := db.Users.Query().
		Select(
			users.FieldID,
			users.FieldUsername,
		).
		Where(
			users.UsernameEQ(username),
			users.UserStatusEQ(int(adminv1.User_ACTIVE.Number())),
		).
		WithLionUserIdentities(func(q *lion.UserIdentitiesQuery) {
			q.Select(
				useridentities.FieldID,
				useridentities.FieldUserID,
				useridentities.FieldProviderID,
				useridentities.FieldPasswordHash,
			).Where(
				useridentities.ProviderIDEQ(provider.ID),
			)
		}).
		Only(ctx)
	if err != nil {
		return false
	}

	if len(u.Edges.LionUserIdentities) == 0 {
		return false
	}

	identity := u.Edges.LionUserIdentities[0]
	if identity.PasswordHash == "" {
		return false
	}

	// bcrypt 比较：identity.PasswordHash 是 bcrypt 哈希，passwordHash 是 SHA256 十六进制
	if err := crypto.BcryptCompare(identity.PasswordHash, passwordHash); err != nil {
		return false
	}

	return true
}

// RevealCredentialSecret 揭示凭证密钥
// 通过当前用户密码二次验证后，解密并返回凭证的敏感字段。
// 安全约束：
// - 从 context 获取当前用户名，与 password_hash 一起验证身份
// - 支持静态用户和数据库注册用户两种验证方式
// - 验证失败返回 Unauthenticated
// - 按凭证类型仅解密并返回该类型实际拥有的字段
// - 操作记录审计日志
func (a *KnownAdminAPI) RevealCredentialSecret(ctx context.Context, req *adminv1.RevealCredentialSecretRequest) (*adminv1.RevealCredentialSecretResponse, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("credential id is required")
	}

	if req.PasswordHash == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("password_hash is required")
	}

	// 从 context 获取当前用户名
	username, ok := rpc.GetUsernameFromContext(ctx)
	if !ok || username == "" || username == "anonymous" {
		return nil, errs.Unauthenticated(ctx).WithMessage("unable to determine current user")
	}

	// 验证当前用户密码（支持静态用户和数据库用户）
	if !a.verifyUserPassword(ctx, username, req.PasswordHash) {
		return nil, errs.Unauthenticated(ctx).WithMessage("password verification failed")
	}

	// 获取数据库客户端
	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	// 查询凭证记录
	row, err := db.Credentials.Get(ctx, int(req.Id))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.NotFound(ctx).WithMessage("credential not found")
		}
		return nil, err
	}

	result := &adminv1.RevealCredentialSecretResponse{
		Id: int64(row.ID),
	}

	// 根据凭证类型解密对应字段
	switch row.CredentialType {
	case int(adminv1.Credential_API_KEY.Number()):
		if len(row.APISecretEncrypted) > 0 {
			plain, err := crypto.DecryptAES(a.config.aesKey, row.APISecretEncrypted)
			if err != nil {
				return nil, errs.Internal(ctx).WithMessage("failed to decrypt api_secret: " + err.Error())
			}
			result.ApiSecret = plain
		}
	case int(adminv1.Credential_SYMMETRIC_KEY.Number()), int(adminv1.Credential_SECRET.Number()):
		if len(row.SymmetricKeyEncrypted) > 0 {
			plain, err := crypto.DecryptAES(a.config.aesKey, row.SymmetricKeyEncrypted)
			if err != nil {
				return nil, errs.Internal(ctx).WithMessage("failed to decrypt symmetric_key: " + err.Error())
			}
			result.SymmetricKey = plain
		}
	case int(adminv1.Credential_KEY_PAIR.Number()), int(adminv1.Credential_X509.Number()):
		if len(row.PrivateKeyEncrypted) > 0 {
			plain, err := crypto.DecryptAES(a.config.aesKey, row.PrivateKeyEncrypted)
			if err != nil {
				return nil, errs.Internal(ctx).WithMessage("failed to decrypt private_key: " + err.Error())
			}
			result.PrivateKey = plain
		}
		if len(row.PassphraseEncrypted) > 0 {
			plain, err := crypto.DecryptAES(a.config.aesKey, row.PassphraseEncrypted)
			if err != nil {
				return nil, errs.Internal(ctx).WithMessage("failed to decrypt passphrase: " + err.Error())
			}
			result.Passphrase = plain
		}
	case int(adminv1.Credential_LICENSE.Number()):
		if len(row.LicenseKeyEncrypted) > 0 {
			plain, err := crypto.DecryptAES(a.config.aesKey, row.LicenseKeyEncrypted)
			if err != nil {
				return nil, errs.Internal(ctx).WithMessage("failed to decrypt license_key: " + err.Error())
			}
			result.LicenseKey = plain
		}
	default:
		return nil, errs.InvalidArgument(ctx).WithMessage("unsupported credential type for reveal")
	}

	// 审计日志
	userID, _ := GetUserID(ctx)
	a.config.logger.Infof("credential secret revealed: credential_id=%d, credential_code=%s, credential_type=%d, operator=%s(%d)",
		row.ID, row.Code, row.CredentialType, username, userID)

	return result, nil
}

// GetOAuth2Discovery 获取内置 OpenID 配置
func (a *KnownAdminAPI) GetOAuth2Discovery(ctx context.Context, req *emptypb.Empty) (*adminv1.OAuth2Discovery, error) {
	result := &adminv1.OAuth2Discovery{}

	issuer := "http://127.0.0.1:8080/builtin/admin/api/v1/oauth2"

	if a.config.issuer != "" {
		issuer = a.config.issuer
	}

	result.Issuer = issuer
	result.AuthorizationEndpoint = issuer + "/authorize"
	result.TokenEndpoint = issuer + "/token"
	result.JwksUri = issuer + "/jwks"

	result.ResponseTypesSupported = []string{"none"}
	result.SubjectTypesSupported = []string{"public"}
	result.IdTokenSigningAlgValuesSupported = []string{"RS256"}

	return result, nil
}

// GetOAuth2JSONWebKeys 获取内置 OpenID 公钥
func (a *KnownAdminAPI) GetOAuth2JSONWebKeys(ctx context.Context, req *emptypb.Empty) (*adminv1.OAuth2JSONWebKeys, error) {
	result := &adminv1.OAuth2JSONWebKeys{
		Keys: make([]*adminv1.OAuth2JSONWebKeys_Key, 0),
	}

	sks, err := a.config.db.Credentials.Query().
		Select(
			credentials.FieldKeyID,
			credentials.FieldPublicKey,
		).
		Where(
			credentials.CredentialTypeEQ(int(adminv1.Credential_KEY_PAIR.Number())),
			credentials.CredentialAlgorithmEQ(int(adminv1.Credential_RSA.Number())),
			credentials.CredentialUsageEQ(int(adminv1.Credential_JWKS.Number())),
			credentials.CredentialVisibilityEQ(int(adminv1.Visibility_VISIBILITY_RESTRICTED.Number())),
			credentials.CredentialStatusEQ(int(adminv1.Credential_ACTIVE.Number())),
			credentials.CredentialSourceEQ(int(adminv1.Credential_SYSTEM.Number())),
		).
		Order(credentials.ByID()).
		All(ctx)
	if err != nil {
		return nil, err
	}

	for _, sk := range sks {
		pubInterface, err := x509.ParsePKIXPublicKey(sk.PublicKey)
		if err != nil {
			a.logger.Errorf("oauth2 jwks: failed to parse public_key (len=%d, firstByte=0x%02x): %v", len(sk.PublicKey), firstByte(sk.PublicKey), err)
			return nil, errs.Internal(ctx).WithMessage("failed to parse JWKS public key").Err()
		}

		publicKey, ok := pubInterface.(*rsa.PublicKey)
		if !ok {
			return nil, errs.Internal(ctx).WithMessage("JWKS public key is not RSA").Err()
		}

		// 将模数 N 和指数 E 转换为 Base64URL 编码
		n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())

		result.Keys = append(result.Keys, &adminv1.OAuth2JSONWebKeys_Key{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			E:   e,
			N:   n,
			Kid: sk.KeyID,
		})
	}

	return result, nil
}

// GetOAuth2Userinfo 获取内置 OpenID 用户信息
// 对应 OIDC userinfo endpoint，返回 OIDC Standard Claims 规范定义的用户信息
// https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse
func (a *KnownAdminAPI) GetOAuth2Userinfo(ctx context.Context, req *emptypb.Empty) (*adminv1.OAuth2Userinfo, error) {
	result := &adminv1.OAuth2Userinfo{}

	tmp := rpc.GetIDTokenFromContext(ctx)
	a.logger.Infof("get id token type: %v", reflect.TypeOf(tmp))
	idToken, ok := tmp.(auth.IDTokenClaims)
	if !ok {
		return result, errs.PermissionDenied(ctx)
	}

	// 从 JWT 中提取基础 claim（这些字段在签发 token 时已确定）
	result.Sub = idToken.Subject
	result.UserId = idToken.GetMustUserID()
	result.PreferredUsername = idToken.Username
	result.Email = idToken.Email
	result.EmailVerified = idToken.EmailVerified

	// 从数据库查询用户实体，补充完整 OIDC Standard Claims
	userID := result.UserId
	if userID <= 0 {
		// 缺少 user_id 时仅返回 JWT 中的基础 claim
		return result, nil
	}

	user, err := a.config.db.Users.Query().
		Select(
			users.FieldID,
			users.FieldNickname,
			users.FieldProfile,
			users.FieldPicture,
			users.FieldWebsite,
			users.FieldGender,
			users.FieldBirthdate,
			users.FieldTimezone,
			users.FieldLocale,
			users.FieldEmailVerified,
			users.FieldPhoneNumberVerified,
			users.FieldRealnameEncrypted,
			users.FieldEmailEncrypted,
			users.FieldPhoneNumberEncrypted,
			users.FieldUpdatedAt,
		).
		Where(users.IDEQ(int(userID))).
		Only(ctx)
	if err != nil {
		// 用户查询失败时降级返回 JWT 中的基础 claim，避免 userinfo endpoint 整体不可用
		if lion.IsNotFound(err) {
			a.logger.Infof("oauth2 userinfo: user %d not found, returning jwt claims only", userID)
			return result, nil
		}
		a.logger.Infof("oauth2 userinfo: query user %d failed: %v, returning jwt claims only", userID, err)
		return result, nil
	}

	result.Nickname = user.Nickname
	result.Profile = user.Profile
	result.Picture = user.Picture
	result.Website = user.Website
	result.Zoneinfo = user.Timezone
	result.Locale = user.Locale
	result.PhoneNumberVerified = user.PhoneNumberVerified

	// email_verified 以数据库值为准（JWT 中可能过期）
	if user.EmailVerified {
		result.EmailVerified = true
	}

	// realname 解密映射到 OIDC name claim；若 realname 为空则回退到 nickname
	realname, err := a.decryptStringField(ctx, users.FieldRealnameEncrypted, user.RealnameEncrypted)
	if err != nil {
		return nil, err
	}
	if realname != "" {
		result.Name = realname
	} else {
		result.Name = user.Nickname
	}

	// email 解密（JWT 中 email 可能为空或过期，以数据库为准）
	email, err := a.decryptStringField(ctx, users.FieldEmailEncrypted, user.EmailEncrypted)
	if err != nil {
		return nil, err
	}
	if email != "" {
		result.Email = email
	}

	// phone_number 解密并格式化为 E.164 字符串
	phoneNumber, err := a.decryptPhoneNumberField(ctx, user.PhoneNumberEncrypted)
	if err != nil {
		return nil, err
	}
	if phoneNumber != nil && phoneNumber.GetCountryCode() != "" && phoneNumber.GetNationalNumber() != "" {
		result.PhoneNumber = fmt.Sprintf("+%s%s", phoneNumber.GetCountryCode(), phoneNumber.GetNationalNumber())
	}

	// gender enum → OIDC string
	result.Gender = genderToOIDCString(adminv1.User_Gender(user.Gender))

	// birthdate Timestamp → ISO 8601 "YYYY-MM-DD" 字符串
	if user.Birthdate != nil {
		result.Birthdate = user.Birthdate.Format("2006-01-02")
	}

	// updated_at → Unix 时间戳（秒）
	result.UpdatedAt = user.UpdatedAt.Unix()

	return result, nil
}

// firstByte 返回字节切片的首字节，空切片返回 0。
func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}

// timePtr 返回给定 time.Time 的指针
func timePtr(t time.Time) *time.Time {
	return &t
}

// genderToOIDCString 将 User.Gender enum 映射为 OIDC Standard Claims 规范的 gender 字符串值
// OIDC 规范未强制枚举，常见值为 "male"/"female"/"other"；PRIVATE 和 UNSPECIFIED 返回空字符串（不返回该 claim）
func genderToOIDCString(g adminv1.User_Gender) string {
	switch g {
	case adminv1.User_MALE:
		return "male"
	case adminv1.User_FEMALE:
		return "female"
	case adminv1.User_OTHER:
		return "other"
	default:
		// GENDER_UNSPECIFIED / PRIVATE 不返回
		return ""
	}
}
