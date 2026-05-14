package admin

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/globalsettings"
	"github.com/grpc-kit/pkg/lion/roles"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (a *KnownAdminAPI) GetGlobalSettings(ctx context.Context, req *adminv1.GetGlobalSettingsRequest) (*adminv1.GlobalSettingCategory, error) {
	if err := a.checkGlobalSettingsReadPermission(ctx); err != nil {
		return nil, err
	}

	category := strings.TrimSpace(req.GetCategory())
	if category == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("category is required")
	}

	settings, err := a.buildGlobalSettingCategory(ctx, category)
	if err != nil {
		return nil, err
	}
	return settings, nil
}

func (a *KnownAdminAPI) ListGlobalSettings(ctx context.Context, req *adminv1.ListGlobalSettingsRequest) (*adminv1.ListGlobalSettingsResponse, error) {
	_ = req
	if err := a.checkGlobalSettingsReadPermission(ctx); err != nil {
		return nil, err
	}

	result := &adminv1.ListGlobalSettingsResponse{Categories: make([]*adminv1.GlobalSettingCategory, 0, len(globalSettingRegistry))}

	categories := make([]string, 0, len(globalSettingRegistry))
	for category := range globalSettingRegistry {
		categories = append(categories, category)
	}
	sort.Strings(categories)

	for _, category := range categories {
		settings, err := a.buildGlobalSettingCategory(ctx, category)
		if err != nil {
			return nil, err
		}
		result.Categories = append(result.Categories, settings)
	}

	return result, nil
}

func (a *KnownAdminAPI) UpdateGlobalSettings(ctx context.Context, req *adminv1.UpdateGlobalSettingsRequest) (*adminv1.UpdateGlobalSettingsResponse, error) {
	category := strings.TrimSpace(req.GetCategory())
	if category == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("category is required")
	}
	if _, ok := globalSettingRegistry[category]; !ok {
		return nil, errs.InvalidArgument(ctx).WithMessage("unknown category")
	}
	if len(req.GetUpdates()) == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("updates are required")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}
	if err := a.checkGlobalSettingsWritePermission(ctx, db); err != nil {
		return nil, err
	}

	validated, err := validateGlobalSettingsUpdates(req)
	if err != nil {
		return nil, err
	}

	var actor int64
	if userID, userErr := GetUserID(ctx); userErr == nil {
		actor = userID
	}

	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to begin transaction")
	}
	defer func() { _ = tx.Rollback() }()

	for _, item := range validated {
		existing, queryErr := tx.GlobalSettings.Query().
			Where(
				globalsettings.CategoryEQ(category),
				globalsettings.SettingKeyEQ(item.settingKey),
			).
			Only(ctx)
		if queryErr != nil && !lion.IsNotFound(queryErr) {
			return nil, errs.Internal(ctx).WithMessage(queryErr.Error())
		}

		if lion.IsNotFound(queryErr) {
			create := tx.GlobalSettings.Create().
				SetCategory(category).
				SetSettingKey(item.settingKey).
				SetSettingValue(item.settingValue).
				SetValueType(string(item.spec.ValueType)).
				SetDescription(item.spec.Description).
				SetProtected(item.spec.Protected)
			if actor != 0 {
				create = create.SetCreatedBy(actor).SetUpdatedBy(actor)
			}
			if _, createErr := create.Save(ctx); createErr != nil {
				return nil, errs.Internal(ctx).WithMessage(createErr.Error())
			}
			continue
		}

		update := tx.GlobalSettings.Update().
			Where(globalsettings.IDEQ(existing.ID)).
			SetSettingValue(item.settingValue).
			SetDescription(item.spec.Description)
		if actor != 0 {
			update = update.SetUpdatedBy(actor)
		}
		if _, updateErr := update.Save(ctx); updateErr != nil {
			return nil, errs.Internal(ctx).WithMessage(updateErr.Error())
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to commit global settings update")
	}

	categoryResp, err := a.buildGlobalSettingCategory(ctx, category)
	if err != nil {
		return nil, err
	}
	return &adminv1.UpdateGlobalSettingsResponse{Category: categoryResp}, nil
}

func (a *KnownAdminAPI) checkGlobalSettingsReadPermission(ctx context.Context) error {
	userRoleIDs, err := a.getUserRoleID(ctx)
	if err != nil {
		return err
	}
	if len(userRoleIDs) == 0 {
		return errs.PermissionDenied(ctx).WithMessage("user has no roles")
	}
	return nil
}

func (a *KnownAdminAPI) checkGlobalSettingsWritePermission(ctx context.Context, db *lion.Client) error {
	userRoleIDs, err := a.getUserRoleID(ctx)
	if err != nil {
		return err
	}
	if len(userRoleIDs) == 0 {
		return errs.PermissionDenied(ctx).WithMessage("user has no roles")
	}

	superadminCode := seedRoleCode(adminv1.RoleCode_ROLE_CODE_SUPERADMIN)
	hasSuperadminRole, err := db.Roles.Query().
		Where(
			roles.IDIn(userRoleIDs...),
			roles.CodeEQ(superadminCode),
		).
		Exist(ctx)
	if err != nil {
		return errs.Internal(ctx).WithMessage(err.Error())
	}
	if !hasSuperadminRole {
		return errs.PermissionDenied(ctx).WithMessage("global settings write requires superadmin role")
	}

	return nil
}

type validatedGlobalSettingUpdate struct {
	settingKey   string
	settingValue string
	spec         globalSettingSpec
}

func validateGlobalSettingsUpdates(req *adminv1.UpdateGlobalSettingsRequest) ([]validatedGlobalSettingUpdate, error) {
	seen := make(map[string]struct{}, len(req.GetUpdates()))
	validated := make([]validatedGlobalSettingUpdate, 0, len(req.GetUpdates()))

	for _, update := range req.GetUpdates() {
		settingKey := strings.TrimSpace(update.GetSettingKey())
		if settingKey == "" {
			return nil, errs.InvalidArgument(context.Background()).WithMessage("setting_key is required")
		}
		if _, exists := seen[settingKey]; exists {
			return nil, errs.InvalidArgument(context.Background()).WithMessage(fmt.Sprintf("duplicate setting_key: %s", settingKey))
		}
		seen[settingKey] = struct{}{}

		spec, ok := lookupGlobalSettingSpec(req.GetCategory(), settingKey)
		if !ok {
			return nil, errs.InvalidArgument(context.Background()).WithMessage(fmt.Sprintf("unknown setting_key: %s", settingKey))
		}

		value := strings.TrimSpace(update.GetSettingValue())
		if err := validateGlobalSettingValue(settingKey, value, spec); err != nil {
			return nil, err
		}

		validated = append(validated, validatedGlobalSettingUpdate{
			settingKey:   settingKey,
			settingValue: value,
			spec:         spec,
		})
	}

	return validated, nil
}

func validateGlobalSettingValue(settingKey, value string, spec globalSettingSpec) error {
	switch spec.ValueType {
	case globalSettingValueTypeBool:
		if _, err := strconv.ParseBool(value); err != nil {
			return errs.InvalidArgument(context.Background()).WithMessage(fmt.Sprintf("invalid bool for %s: %q", settingKey, value))
		}
	case globalSettingValueTypeInt:
		parsed, err := strconv.Atoi(value)
		if err != nil {
			return errs.InvalidArgument(context.Background()).WithMessage(fmt.Sprintf("invalid int for %s: %q", settingKey, value))
		}
		if spec.MinInt != nil && parsed < *spec.MinInt {
			return errs.InvalidArgument(context.Background()).WithMessage(fmt.Sprintf("%s must be >= %d", settingKey, *spec.MinInt))
		}
		if spec.MaxInt != nil && parsed > *spec.MaxInt {
			return errs.InvalidArgument(context.Background()).WithMessage(fmt.Sprintf("%s must be <= %d", settingKey, *spec.MaxInt))
		}
	case globalSettingValueTypeDuration:
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return errs.InvalidArgument(context.Background()).WithMessage(fmt.Sprintf("invalid duration for %s: %q", settingKey, value))
		}
		if spec.MinDuration != nil && parsed < *spec.MinDuration {
			return errs.InvalidArgument(context.Background()).WithMessage(fmt.Sprintf("%s must be >= %s", settingKey, spec.MinDuration.String()))
		}
		if spec.MaxDuration != nil && parsed > *spec.MaxDuration {
			return errs.InvalidArgument(context.Background()).WithMessage(fmt.Sprintf("%s must be <= %s", settingKey, spec.MaxDuration.String()))
		}
	case globalSettingValueTypeString:
		if spec.MaxLen > 0 && len(value) > spec.MaxLen {
			return errs.InvalidArgument(context.Background()).WithMessage(fmt.Sprintf("%s length must be <= %d", settingKey, spec.MaxLen))
		}
	default:
		return errs.InvalidArgument(context.Background()).WithMessage(fmt.Sprintf("unsupported value_type for %s", settingKey))
	}

	return nil
}

func (a *KnownAdminAPI) buildGlobalSettingCategory(ctx context.Context, category string) (*adminv1.GlobalSettingCategory, error) {
	specs, ok := globalSettingRegistry[category]
	if !ok {
		return nil, errs.InvalidArgument(ctx).WithMessage("unknown category")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}

	rows, err := db.GlobalSettings.Query().
		Where(globalsettings.CategoryEQ(category)).
		All(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage(err.Error())
	}

	rowByKey := make(map[string]*lion.GlobalSettings, len(rows))
	for _, row := range rows {
		rowByKey[row.SettingKey] = row
	}

	keys := make([]string, 0, len(specs))
	for settingKey := range specs {
		keys = append(keys, settingKey)
	}
	sort.Strings(keys)

	result := &adminv1.GlobalSettingCategory{
		Category: category,
		Settings: make([]*adminv1.GlobalSetting, 0, len(keys)),
	}
	for _, settingKey := range keys {
		spec := specs[settingKey]
		if row, ok := rowByKey[settingKey]; ok {
			result.Settings = append(result.Settings, toProtoGlobalSetting(row))
			continue
		}
		result.Settings = append(result.Settings, &adminv1.GlobalSetting{
			Category:     category,
			SettingKey:   settingKey,
			SettingValue: spec.DefaultValue,
			ValueType:    string(spec.ValueType),
			Description:  spec.Description,
			Protected:    spec.Protected,
		})
	}

	return result, nil
}

func toProtoGlobalSetting(row *lion.GlobalSettings) *adminv1.GlobalSetting {
	result := &adminv1.GlobalSetting{
		Id:           int64(row.ID),
		Category:     row.Category,
		SettingKey:   row.SettingKey,
		SettingValue: row.SettingValue,
		ValueType:    row.ValueType,
		Description:  row.Description,
		Protected:    row.Protected,
		CreatedBy:    row.CreatedBy,
		UpdatedBy:    row.UpdatedBy,
	}
	if !row.CreatedAt.IsZero() {
		result.CreatedAt = timestamppb.New(row.CreatedAt)
	}
	if !row.UpdatedAt.IsZero() {
		result.UpdatedAt = timestamppb.New(row.UpdatedAt)
	}
	return result
}
