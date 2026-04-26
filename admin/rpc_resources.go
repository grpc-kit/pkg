package admin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/policies"
	"github.com/grpc-kit/pkg/lion/policyattachments"
	"github.com/grpc-kit/pkg/lion/predicate"
	"github.com/grpc-kit/pkg/lion/resources"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/lion/schema"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// listResourceAuthFilter 用于在新策略链路中收窄可见资源；零值表示不按该维度过滤。
type listResourceAuthFilter struct {
	PolicyType   int32
	PolicyStatus int32
}

func parseSelectorPatterns(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	var list []string
	if strings.HasPrefix(raw, "[") {
		if err := json.Unmarshal([]byte(raw), &list); err == nil {
			return compactNonEmptyStrings(list)
		}
	}

	var single string
	if strings.HasPrefix(raw, "\"") {
		if err := json.Unmarshal([]byte(raw), &single); err == nil {
			return compactNonEmptyStrings([]string{single})
		}
	}

	return []string{raw}
}

func compactNonEmptyStrings(items []string) []string {
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		result = append(result, item)
	}
	return result
}

func wildcardMatch(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	quoted := regexp.QuoteMeta(pattern)
	quoted = strings.ReplaceAll(quoted, "\\*", ".*")
	matched, err := regexp.MatchString("^"+quoted+"$", value)
	return err == nil && matched
}

func policyStatementMatchesResource(statement *lion.PolicyStatements, resource *lion.Resources) bool {
	if statement == nil || resource == nil {
		return false
	}

	selectors := parseSelectorPatterns(statement.ResourceSelector)
	if len(selectors) == 0 {
		return false
	}

	resourceTypeCode := resource.ResourceTypeCode
	if resourceTypeCode == "" {
		resourceTypeCode = resourceTypeCodeFromLegacy(resource.ResourceType)
	}
	serviceCode := resource.ServiceCode
	if serviceCode == "" {
		serviceCode = "admin.v1.oneops"
	}
	resourcePath := normalizeResourcePath(resource.ResourcePath, resource.Code, resource.Locator)
	grn := resource.Grn
	if grn == "" {
		grn = buildResourceGRN(serviceCode, resource.TenantID, resource.Region, resourceTypeCode, resourcePath, resource.Name)
	}

	candidates := []string{grn, resource.Name, resource.Code, resourcePath}
	for _, selector := range selectors {
		for _, candidate := range candidates {
			if candidate != "" && wildcardMatch(selector, candidate) {
				return true
			}
		}
	}
	return false
}

// allowedResourceIDsForContext 按当前用户角色树、策略挂载和 policy statements.resource_selector 解析当前用户可访问的资源 ID 集合。
// superAdmin 为 true 时不返回 allowed（调用方视为不裁剪）；err 表示上下文缺失 groups 等错误。
func (a *KnownAdminAPI) allowedResourceIDsForContext(ctx context.Context, db *lion.Client, f listResourceAuthFilter) (superAdmin bool, allowed map[int]struct{}, err error) {
	gs, ok := rpc.GetGroupsFromContext(ctx)
	if !ok {
		return false, nil, fmt.Errorf("not found groups")
	}
	if len(gs) == 0 {
		return false, map[int]struct{}{}, nil
	}
	for _, g := range gs {
		if g == "superadmin" {
			return true, nil, nil
		}
	}
	roleRows, err := db.Roles.Query().Select(roles.FieldID).Where(roles.CodeIn(gs...)).All(ctx)
	if err != nil {
		return false, nil, err
	}
	if len(roleRows) == 0 {
		return false, map[int]struct{}{}, nil
	}
	parentRoleIDs := make([]int, len(roleRows))
	for i, r := range roleRows {
		parentRoleIDs[i] = r.ID
	}
	childRoleIDs, err := a.getAllChildRoleIDs(ctx, db, parentRoleIDs)
	if err != nil {
		return false, nil, err
	}
	allRoleIDs := mergeUniqueInts(parentRoleIDs, childRoleIDs)
	allRoleID64s := make([]int64, 0, len(allRoleIDs))
	for _, id := range allRoleIDs {
		allRoleID64s = append(allRoleID64s, int64(id))
	}

	policiesWhere := make([]predicate.Policies, 0)
	if f.PolicyType != 0 {
		policiesWhere = append(policiesWhere, policies.PolicyTypeEQ(int(f.PolicyType)))
	}
	if f.PolicyStatus != 0 {
		policiesWhere = append(policiesWhere, policies.PolicyStatusEQ(int(f.PolicyStatus)))
	}

	attachmentQuery := db.PolicyAttachments.Query().
		Where(
			policyattachments.PrincipalTypeEQ("ROLE"),
			policyattachments.PrincipalIDIn(allRoleID64s...),
			policyattachments.AttachmentStatusIn(
				int(adminv1.PolicyAttachment_STATUS_UNSPECIFIED),
				int(adminv1.PolicyAttachment_ACTIVE),
			),
			policyattachments.Or(
				policyattachments.ExpiresAtIsNil(),
				policyattachments.ExpiresAtGT(time.Now()),
			),
		).
		WithLionPolicies(func(query *lion.PoliciesQuery) {
			if len(policiesWhere) > 0 {
				query.Where(policiesWhere...)
			}
			query.WithLionPolicyStatements()
		})

	attachments, err := attachmentQuery.All(ctx)
	if err != nil {
		return false, nil, err
	}
	if len(attachments) == 0 {
		return false, map[int]struct{}{}, nil
	}

	resourceList, err := db.Resources.Query().All(ctx)
	if err != nil {
		return false, nil, err
	}
	if len(resourceList) == 0 {
		return false, map[int]struct{}{}, nil
	}

	allowedIDs := make(map[int]struct{})
	deniedIDs := make(map[int]struct{})
	for _, attachment := range attachments {
		policy := attachment.Edges.LionPolicies
		if policy == nil {
			continue
		}
		for _, statement := range policy.Edges.LionPolicyStatements {
			if statement == nil {
				continue
			}
			for _, resource := range resourceList {
				if !policyStatementMatchesResource(statement, resource) {
					continue
				}
				if statement.Effect == int(adminv1.PolicyStatement_DENY) {
					deniedIDs[resource.ID] = struct{}{}
					delete(allowedIDs, resource.ID)
					continue
				}
				if statement.Effect == int(adminv1.PolicyStatement_ALLOW) {
					if _, denied := deniedIDs[resource.ID]; !denied {
						allowedIDs[resource.ID] = struct{}{}
					}
				}
			}
		}
	}
	return false, allowedIDs, nil
}

// ensureResourceIDAllowed 非 superadmin 时要求 resourceID 落在 allowed 集合中；否则返回 NotFound（与「资源不存在」统一，避免泄漏）。
func ensureResourceIDAllowed(ctx context.Context, superAdmin bool, allowed map[int]struct{}, resourceID int) error {
	if superAdmin {
		return nil
	}
	if _, ok := allowed[resourceID]; !ok {
		return errs.NotFound(ctx).WithMessage("resource not found")
	}
	return nil
}

func (a *KnownAdminAPI) defaultServiceCode() string {
	return "admin.v1.oneops"
}

func resourceTypeCodeFromLegacy(resourceType int) string {
	switch adminv1.Resource_Type(resourceType) {
	case adminv1.Resource_MENU:
		return "sys_menu"
	case adminv1.Resource_API:
		return "sys_api"
	default:
		return "sys_object"
	}
}

func normalizeResourcePath(path, code, locator string) string {
	path = strings.TrimSpace(path)
	if path != "" {
		return path
	}
	locator = strings.TrimSpace(locator)
	if locator != "" {
		return locator
	}
	code = strings.TrimSpace(code)
	if code != "" {
		return code
	}
	return "*"
}

func buildResourceGRN(serviceCode, tenantID, region, resourceTypeCode, resourcePath, legacyName string) string {
	if strings.TrimSpace(legacyName) != "" {
		return legacyName
	}
	if serviceCode == "" || resourceTypeCode == "" {
		return ""
	}
	return fmt.Sprintf("grn:%s:%s:%s:%s/%s", serviceCode, tenantID, region, resourceTypeCode, resourcePath)
}

func (a *KnownAdminAPI) lionResourceToProto(in *lion.Resources) *adminv1.Resource {
	if in == nil {
		return nil
	}

	resourceTypeCode := in.ResourceTypeCode
	if resourceTypeCode == "" {
		resourceTypeCode = resourceTypeCodeFromLegacy(in.ResourceType)
	}
	serviceCode := in.ServiceCode
	if serviceCode == "" {
		serviceCode = a.defaultServiceCode()
	}
	resourcePath := normalizeResourcePath(in.ResourcePath, in.Code, in.Locator)
	grn := in.Grn
	if grn == "" {
		grn = buildResourceGRN(serviceCode, in.TenantID, in.Region, resourceTypeCode, resourcePath, in.Name)
	}

	return &adminv1.Resource{
		Id:               int64(in.ID),
		ParentId:         in.ParentID,
		Code:             in.Code,
		Name:             in.Name,
		DisplayName:      in.DisplayName,
		SortOrder:        int32(in.SortOrder),
		Type:             adminv1.Resource_Type(in.ResourceType),
		Status:           adminv1.Resource_Status(in.ResourceStatus),
		Visibility:       adminv1.Visibility(in.Visibility),
		Locator:          in.Locator,
		Visual:           in.Visual,
		Manifest:         in.Manifest,
		Description:      in.Description,
		CreatedBy:        in.CreatedBy,
		UpdatedBy:        in.UpdatedBy,
		CreatedAt:        timestamppb.New(in.CreatedAt),
		UpdatedAt:        timestamppb.New(in.UpdatedAt),
		ResourceTypeCode: resourceTypeCode,
		ServiceCode:      serviceCode,
		TenantId:         in.TenantID,
		Region:           in.Region,
		ResourcePath:     resourcePath,
		Grn:              grn,
		Scopes:           nil,
	}
}

// ListResources 获取资源列表
func (a *KnownAdminAPI) ListResources(ctx context.Context, req *adminv1.ListResourcesRequest) (*adminv1.ListResourcesResponse, error) {
	result := &adminv1.ListResourcesResponse{}

	// TODO；读取该用户的缓存

	db, err := a.GetLionClient()
	if err != nil {
		// 如果未开启数据库时直接返回空资源而不是错误
		return result, nil
	}

	hasSuperAdmin, allowedIDs, err := a.allowedResourceIDsForContext(ctx, db, listResourceAuthFilter{
		PolicyType:   req.PolicyType,
		PolicyStatus: req.PolicyStatus,
	})
	if err != nil {
		return result, err
	}

	// 3 获取资源列表
	resourcesWhere := make([]predicate.Resources, 0)

	if !hasSuperAdmin {
		if len(allowedIDs) == 0 {
			return result, nil
		}
		resourcesWhere = append(resourcesWhere, resources.IDIn(mapKeys(allowedIDs)...))
	}

	if req.ResourceType != 0 {
		if resourceType, err := a.resolveResourceTypeForLegacy(ctx, db, adminv1.Resource_Type(req.ResourceType)); err == nil {
			resourcesWhere = append(resourcesWhere, resources.Or(
				resources.ResourceTypeIDEQ(resourceType.ID),
				resources.ResourceTypeEQ(int(req.ResourceType)),
			))
		} else {
			resourcesWhere = append(resourcesWhere, resources.ResourceTypeEQ(int(req.ResourceType)))
		}
	}
	if req.ResourceStatus != 0 {
		resourcesWhere = append(resourcesWhere, resources.ResourceStatusEQ(int(req.ResourceStatus)))
	}

	// 构建查询，但先不执行
	resourceQuery := db.Resources.Query().Where(resourcesWhere...)

	// 处理排序
	if req.OrderBy != "" {
		switch req.OrderBy {
		case "sort_order asc":
			resourceQuery = resourceQuery.Order(lion.Asc(resources.FieldSortOrder))
		case "sort_order desc":
			resourceQuery = resourceQuery.Order(lion.Desc(resources.FieldSortOrder))
		case "create_time desc":
			resourceQuery = resourceQuery.Order(lion.Desc(resources.FieldCreatedAt))
		case "create_time asc":
			resourceQuery = resourceQuery.Order(lion.Asc(resources.FieldCreatedAt))
		default:
			// 默认按 sort_order 升序，然后按 ID 升序
			resourceQuery = resourceQuery.Order(lion.Asc(resources.FieldSortOrder), lion.Asc(resources.FieldID))
		}
	} else {
		// 默认排序
		resourceQuery = resourceQuery.Order(lion.Asc(resources.FieldSortOrder), lion.Asc(resources.FieldID))
	}

	// 计算总数（在应用分页前）
	totalSize, err := resourceQuery.Clone().Count(ctx)
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
			resourceQuery = resourceQuery.Where(resources.IDGT(lastID))
		}
	}

	switch p := req.GetPagination().(type) {
	case *adminv1.ListResourcesRequest_Offset:
		// Offset-based 分页
		resourceQuery = resourceQuery.Offset(int(p.Offset))
	case *adminv1.ListResourcesRequest_PageToken:
		// Cursor-based 分页已在上面处理
	}

	// 应用 Limit
	resourceQuery = resourceQuery.Limit(int(pageSize))

	// 执行查询

	resList, err := resourceQuery.All(ctx)
	if err != nil {
		return nil, err
	}

	switch req.Structure.String() {
	case adminv1.Structure_STRUCTURE_TREE.String():
		// 构建树状菜单
		// 注意：树状结构的分页比较特殊，这里先构建完整的树，实际项目中可能需要调整策略
		menuMap := make(map[int64]*adminv1.Resource)
		var roots []*adminv1.Resource

		for _, m := range resList {
			menu := &adminv1.Resource{
				Id:          int64(m.ID),
				ParentId:    m.ParentID,
				Code:        m.Code,
				Name:        m.Name,
				DisplayName: m.DisplayName,
				SortOrder:   int32(m.SortOrder),
				Type:        adminv1.Resource_Type(m.ResourceType),
				// Scope:        adminv1.Resource_Scope(m.ResourceScope),
				Status:     adminv1.Resource_Status(m.ResourceStatus),
				Visibility: adminv1.Visibility(m.Visibility),
				/*
					Hidden:       m.Hidden,
					HideChildren: m.HideChildren,
				*/
				Locator:   m.Locator,
				Visual:    m.Visual,
				Manifest:  m.Manifest,
				CreatedAt: timestamppb.New(m.CreatedAt),
				UpdatedAt: timestamppb.New(m.UpdatedAt),
			}

			menuMap[int64(m.ID)] = menu
		}

		for _, menu := range menuMap {
			if menu.ParentId == 0 {
				roots = append(roots, menu)
				continue
			}

			if parent, ok := menuMap[menu.ParentId]; ok {
				parent.Children = append(parent.Children, menu)
			}
		}

		// 可选：对根菜单排序
		sort.Slice(roots, func(i, j int) bool {
			return roots[i].SortOrder < roots[j].SortOrder
		})

		result.Resources = roots
	default:
		for _, m := range resList {
			resource := a.lionResourceToProto(m)
			result.Resources = append(result.Resources, resource)
		}
	}

	// 构造 next_page_token（仅用于 cursor-based 分页）
	switch req.GetPagination().(type) {
	case *adminv1.ListResourcesRequest_PageToken:
		// 只有在使用 cursor-based 分页时才生成 next_page_token
		if len(resList) == int(pageSize) && len(resList) > 0 {
			last := resList[len(resList)-1].ID
			tokenData, _ := json.Marshal(last)
			result.NextPageToken = base64.StdEncoding.EncodeToString(tokenData)
		}
	}

	return result, nil
}

// CreateResource 创建资源
func (a *KnownAdminAPI) CreateResource(ctx context.Context, req *adminv1.CreateResourceRequest) (*adminv1.Resource, error) {
	if req == nil || req.Resource == nil {
		return nil, fmt.Errorf("request body resource is nil")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	code, err := schema.EnsureCode(req.Resource.Code)
	if err != nil {
		return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
	}
	req.Resource.Code = code
	req.Resource.Name = normalizeResourceName(req.Resource.Name, req.Resource.Type, req.Resource.Code, req.Resource.Locator)

	if req.Resource.ParentId == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("parent_id cannot be 0 when creating resource")
	}

	super, allowed, err := a.allowedResourceIDsForContext(ctx, db, listResourceAuthFilter{})
	if err != nil {
		return nil, err
	}
	if err := ensureResourceIDAllowed(ctx, super, allowed, int(req.Resource.ParentId)); err != nil {
		return nil, err
	}

	parentResource, err := db.Resources.Get(ctx, int(req.Resource.ParentId))
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.InvalidArgument(ctx).WithMessage("parent resource not found")
		}
		return nil, err
	}
	resourceType, err := a.resolveResourceTypeForLegacy(ctx, db, req.Resource.Type)
	if err != nil {
		return nil, err
	}

	if parentResource.ResourceTypeID != 0 {
		if parentResource.ResourceTypeID != resourceType.ID {
			return nil, errs.InvalidArgument(ctx).WithMessage("resource type must match parent resource type")
		}
	} else if parentResource.ResourceType != int(req.Resource.Type) {
		return nil, errs.InvalidArgument(ctx).WithMessage("resource type must match parent resource type")
	}

	// 获取创建者用户 ID
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	// 设置默认值
	sortOrder := int(req.Resource.SortOrder)
	if sortOrder == 0 {
		sortOrder = 100 // 默认排序权重
	}

	// 创建资源
	resourceTypeCode := resourceType.Code
	serviceCode := a.defaultServiceCode()
	resourcePath := normalizeResourcePath(req.Resource.ResourcePath, req.Resource.Code, req.Resource.Locator)
	grn := buildResourceGRN(serviceCode, req.Resource.TenantId, req.Resource.Region, resourceTypeCode, resourcePath, req.Resource.Name)
	newResource, err := db.Resources.Create().
		SetCode(req.Resource.Code).
		SetName(req.Resource.Name).
		SetDisplayName(req.Resource.DisplayName).
		SetResourceType(int(req.Resource.Type)).
		SetResourceTypeID(resourceType.ID).
		SetResourceTypeCode(resourceTypeCode).
		SetServiceCode(serviceCode).
		SetTenantID(req.Resource.TenantId).
		SetRegion(req.Resource.Region).
		SetResourcePath(resourcePath).
		SetGrn(grn).
		SetResourceStatus(int(req.Resource.Status)).
		SetVisibility(int(req.Resource.Visibility)).
		SetParentID(req.Resource.ParentId).
		SetLocator(req.Resource.Locator).
		SetVisual(req.Resource.Visual).
		SetManifest(req.Resource.Manifest).
		SetSortOrder(sortOrder).
		SetDescription(req.Resource.Description).
		SetCreatedBy(userID).
		SetUpdatedBy(userID).
		Save(ctx)

	if err != nil {
		return nil, err
	}

	result := a.lionResourceToProto(newResource)

	// 处理 metadata（如果存在）
	if len(req.Resource.Metadata) > 0 {
		result.Metadata = req.Resource.Metadata
	}

	return result, nil
}

// UpdateResource 更新资源
func (a *KnownAdminAPI) UpdateResource(ctx context.Context, req *adminv1.UpdateResourceRequest) (*adminv1.Resource, error) {
	if req == nil || req.Resource == nil {
		return nil, fmt.Errorf("request body resource is nil")
	}

	if req.Resource.Id == 0 {
		return nil, fmt.Errorf("resource id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	super, allowed, err := a.allowedResourceIDsForContext(ctx, db, listResourceAuthFilter{})
	if err != nil {
		return nil, err
	}
	if err := ensureResourceIDAllowed(ctx, super, allowed, int(req.Resource.Id)); err != nil {
		return nil, err
	}

	// 获取更新者用户 ID
	userID, err := GetUserID(ctx)
	if err != nil {
		return nil, err
	}

	// 查找要更新的资源
	resource, err := db.Resources.Get(ctx, int(req.Resource.Id))
	if err != nil {
		return nil, err
	}

	shouldUpdateParentID := req.UpdateMask == nil || len(req.UpdateMask.Paths) == 0
	if !shouldUpdateParentID {
		for _, field := range req.UpdateMask.Paths {
			if field == resources.FieldParentID {
				shouldUpdateParentID = true
				break
			}
		}
	}
	if shouldUpdateParentID && resource.ParentID == 0 && req.Resource.ParentId != resource.ParentID {
		return nil, errs.InvalidArgument(ctx).WithMessage("root resource parent_id cannot be changed")
	}

	if req.Resource.Code != "" {
		code, err := schema.EnsureCode(req.Resource.Code)
		if err != nil {
			return nil, errs.InvalidArgument(ctx).WithMessage(err.Error())
		}
		req.Resource.Code = code
	}
	effectiveResourceType := req.Resource.Type
	if effectiveResourceType == adminv1.Resource_TYPE_UNSPECIFIED {
		effectiveResourceType = adminv1.Resource_Type(resource.ResourceType)
	}
	req.Resource.Name = normalizeResourceName(req.Resource.Name, effectiveResourceType, req.Resource.Code, req.Resource.Locator)
	resolvedResourceType, err := a.resolveResourceTypeForLegacy(ctx, db, effectiveResourceType)
	if err != nil {
		return nil, err
	}
	resourceTypeCode := resolvedResourceType.Code
	resourcePath := normalizeResourcePath(req.Resource.ResourcePath, req.Resource.Code, req.Resource.Locator)
	serviceCode := resource.ServiceCode
	if serviceCode == "" {
		serviceCode = a.defaultServiceCode()
	}
	grn := buildResourceGRN(serviceCode, req.Resource.TenantId, req.Resource.Region, resourceTypeCode, resourcePath, req.Resource.Name)

	// 构建更新操作
	update := resource.Update()

	// 根据请求设置更新字段
	if req.UpdateMask != nil && len(req.UpdateMask.Paths) > 0 {
		for _, field := range req.UpdateMask.Paths {
			switch field {
			case resources.FieldCode:
				update.SetCode(req.Resource.Code)
			case resources.FieldName:
				update.SetName(req.Resource.Name)
				update.SetGrn(grn)
			case resources.FieldDisplayName:
				update.SetDisplayName(req.Resource.DisplayName)
			case resources.FieldResourceType:
				update.SetResourceType(int(effectiveResourceType))
				update.SetResourceTypeID(resolvedResourceType.ID)
				update.SetResourceTypeCode(resourceTypeCode)
			case resources.FieldResourceStatus:
				update.SetResourceStatus(int(req.Resource.Status))
			case resources.FieldVisibility:
				update.SetVisibility(int(req.Resource.Visibility))
			case resources.FieldParentID:
				update.SetParentID(req.Resource.ParentId)
			case resources.FieldLocator:
				update.SetLocator(req.Resource.Locator)
				update.SetResourcePath(resourcePath)
				update.SetGrn(grn)
			case resources.FieldVisual:
				update.SetVisual(req.Resource.Visual)
			case resources.FieldManifest:
				update.SetManifest(req.Resource.Manifest)
			case resources.FieldSortOrder:
				update.SetSortOrder(int(req.Resource.SortOrder))
			case resources.FieldDescription:
				update.SetDescription(req.Resource.Description)
			case resources.FieldTenantID:
				update.SetTenantID(req.Resource.TenantId)
				update.SetGrn(grn)
			case resources.FieldRegion:
				update.SetRegion(req.Resource.Region)
				update.SetGrn(grn)
			case resources.FieldServiceCode:
				update.SetServiceCode(req.Resource.ServiceCode)
			case resources.FieldResourcePath:
				update.SetResourcePath(req.Resource.ResourcePath)
				update.SetGrn(buildResourceGRN(req.Resource.ServiceCode, req.Resource.TenantId, req.Resource.Region, resourceTypeCode, req.Resource.ResourcePath, req.Resource.Name))
			}
		}
		// 始终更新 UpdatedBy
		update.SetUpdatedBy(userID)
	} else {
		// 如果没有指定更新字段，则更新所有字段
		update.
			SetCode(req.Resource.Code).
			SetName(req.Resource.Name).
			SetDisplayName(req.Resource.DisplayName).
			SetResourceType(int(effectiveResourceType)).
			SetResourceTypeID(resolvedResourceType.ID).
			SetResourceTypeCode(resourceTypeCode).
			SetResourceStatus(int(req.Resource.Status)).
			SetVisibility(int(req.Resource.Visibility)).
			SetParentID(req.Resource.ParentId).
			SetLocator(req.Resource.Locator).
			SetVisual(req.Resource.Visual).
			SetManifest(req.Resource.Manifest).
			SetServiceCode(serviceCode).
			SetTenantID(req.Resource.TenantId).
			SetRegion(req.Resource.Region).
			SetResourcePath(resourcePath).
			SetGrn(grn).
			SetSortOrder(int(req.Resource.SortOrder)).
			SetDescription(req.Resource.Description).
			SetUpdatedBy(userID)
	}

	// 执行更新
	updatedResource, err := update.Save(ctx)
	if err != nil {
		return nil, err
	}

	result := a.lionResourceToProto(updatedResource)

	// 处理 metadata（如果存在）
	if len(req.Resource.Metadata) > 0 {
		result.Metadata = req.Resource.Metadata
	}

	return result, nil
}

// DeleteResource 删除资源
func (a *KnownAdminAPI) DeleteResource(ctx context.Context, req *adminv1.DeleteResourceRequest) (*emptypb.Empty, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("resource id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	super, allowed, err := a.allowedResourceIDsForContext(ctx, db, listResourceAuthFilter{})
	if err != nil {
		return nil, err
	}
	if err := ensureResourceIDAllowed(ctx, super, allowed, int(req.Id)); err != nil {
		return nil, err
	}

	// 检查资源是否存在
	_, err = db.Resources.Get(ctx, int(req.Id))
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("resource not found")
	}

	// 检查是否存在子节点（parent_id == 资源 id）
	childrenCount, err := db.Resources.Query().
		Where(resources.ParentIDEQ(int64(req.Id))).
		Count(ctx)
	if err != nil {
		return nil, err
	}

	if childrenCount > 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("cannot delete resource with child nodes")
	}

	// 执行删除
	err = db.Resources.DeleteOneID(int(req.Id)).Exec(ctx)
	if err != nil {
		return nil, err
	}

	return &emptypb.Empty{}, nil
}

// GetResource 获取单个资源的详细信息
func (a *KnownAdminAPI) GetResource(ctx context.Context, req *adminv1.GetResourceRequest) (*adminv1.Resource, error) {
	if req.Id == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("resource id is required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	super, allowed, err := a.allowedResourceIDsForContext(ctx, db, listResourceAuthFilter{})
	if err != nil {
		return nil, err
	}
	if err := ensureResourceIDAllowed(ctx, super, allowed, int(req.Id)); err != nil {
		return nil, err
	}

	// 查询资源
	resource, err := db.Resources.Query().
		Where(resources.IDEQ(int(req.Id))).
		Only(ctx)
	if err != nil {
		return nil, errs.NotFound(ctx).WithMessage("resource not found")
	}

	return a.lionResourceToProto(resource), nil
}

// collectDescendantIDs 从根节点起 BFS 收集所有子孙资源 ID 并加入 allowedIDs。
func collectDescendantIDs(rootID int64, children map[int64][]int, allowedIDs map[int]struct{}) {
	queue := []int{int(rootID)}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		for _, cid := range children[int64(pid)] {
			allowedIDs[cid] = struct{}{}
			queue = append(queue, cid)
		}
	}
}

// mapKeys 返回 map[int]struct{} 的所有 key，用于 resources.IDIn。
func mapKeys(m map[int]struct{}) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// mergeUniqueInts 合并两段 int 切片并去重，保持先 a 后 b 的稳定顺序。
func mergeUniqueInts(a, b []int) []int {
	seen := make(map[int]struct{}, len(a)+len(b))
	out := make([]int, 0, len(a)+len(b))
	for _, id := range a {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	for _, id := range b {
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

func normalizeResourceName(name string, resourceType adminv1.Resource_Type, code, locator string) string {
	if strings.TrimSpace(name) != "" {
		return strings.TrimSpace(name)
	}
	typePart := strings.ToLower(resourceType.String())
	if typePart == "" || typePart == "type_unspecified" {
		typePart = "resource"
	}
	pathPart := strings.TrimSpace(locator)
	if pathPart == "" {
		pathPart = strings.TrimSpace(code)
	}
	if pathPart == "" {
		pathPart = "unnamed"
	}
	return fmt.Sprintf("grn:admin:default:global:%s:%s", typePart, pathPart)
}
