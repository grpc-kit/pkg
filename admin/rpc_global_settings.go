package admin

import (
	"context"
	"fmt"
	"slices"
	"strings"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/globalsettings"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func (a *KnownAdminAPI) CreateGlobalSetting(ctx context.Context, req *adminv1.CreateGlobalSettingRequest) (*adminv1.GlobalSetting, error) {
	if err := requireConfigSuperadmin(ctx); err != nil {
		return nil, err
	}
	category, err := normalizeGlobalSettingsCategory(ctx, req.GetCategory())
	if err != nil {
		return nil, err
	}
	input := req.GetSetting()
	if input == nil {
		return nil, errs.InvalidArgument(ctx).WithMessage("setting is required")
	}
	settingKey := strings.TrimSpace(input.GetSettingKey())
	if err := validateGlobalSettingKey(ctx, settingKey); err != nil {
		return nil, err
	}
	if _, builtIn := lookupGlobalSettingSpec(category, settingKey); builtIn {
		return nil, errs.AlreadyExists(ctx).WithMessage(fmt.Sprintf("global setting %q already exists", settingKey))
	}
	valueType := globalSettingValueType(strings.TrimSpace(input.GetValueType()))
	if !isSupportedGlobalSettingValueType(valueType) {
		return nil, errs.InvalidArgument(ctx).WithMessage("unsupported value_type")
	}
	description := strings.TrimSpace(input.GetDescription())
	if err := validateGlobalSettingDescription(ctx, description); err != nil {
		return nil, err
	}
	normalizedValue, err := normalizeGlobalSettingValue(ctx, settingKey, input.GetSettingValue(), globalSettingSpec{ValueType: valueType})
	if err != nil {
		return nil, err
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}
	existing, err := db.GlobalSettings.Query().
		Where(globalsettings.CategoryEQ(category), globalsettings.SettingKeyEQ(settingKey)).
		Only(ctx)
	if err == nil && existing != nil {
		return nil, errs.AlreadyExists(ctx).WithMessage(fmt.Sprintf("global setting %q already exists", settingKey))
	}
	if err != nil && !lion.IsNotFound(err) {
		return nil, errs.Internal(ctx).WithMessage("failed to query global setting")
	}

	actor := globalSettingActor(ctx)
	create := db.GlobalSettings.Create().
		SetCategory(category).
		SetSettingKey(settingKey).
		SetSettingValue(normalizedValue).
		SetValueType(string(valueType)).
		SetDescription(description).
		SetProtected(false)
	if actor != 0 {
		create = create.SetCreatedBy(actor).SetUpdatedBy(actor)
	}
	created, err := create.Save(ctx)
	if err != nil {
		a.auditGlobalSettingMutation("create", category, settingKey, actor, "failed")
		if lion.IsConstraintError(err) {
			return nil, errs.AlreadyExists(ctx).WithMessage(fmt.Sprintf("global setting %q already exists", settingKey))
		}
		return nil, errs.Internal(ctx).WithMessage("failed to create global setting")
	}
	a.auditGlobalSettingMutation("create", category, settingKey, actor, "success")
	return toProtoGlobalSetting(created, false), nil
}

func (a *KnownAdminAPI) GetGlobalSettings(ctx context.Context, req *adminv1.GetGlobalSettingsRequest) (*adminv1.GlobalSettingCategory, error) {
	if err := requireConfigSuperadmin(ctx); err != nil {
		return nil, err
	}
	category, err := normalizeGlobalSettingsCategory(ctx, req.GetCategory())
	if err != nil {
		return nil, err
	}
	return a.buildGlobalSettingCategory(ctx, category)
}

func (a *KnownAdminAPI) ListGlobalSettings(ctx context.Context, req *adminv1.ListGlobalSettingsRequest) (*adminv1.ListGlobalSettingsResponse, error) {
	if err := requireConfigSuperadmin(ctx); err != nil {
		return nil, err
	}
	_ = req

	result := &adminv1.ListGlobalSettingsResponse{
		Categories: make([]*adminv1.GlobalSettingCategory, 0, len(globalSettingsCategories)),
	}
	for _, category := range globalSettingsCategories {
		settings, err := a.buildGlobalSettingCategory(ctx, category)
		if err != nil {
			return nil, err
		}
		result.Categories = append(result.Categories, settings)
	}
	return result, nil
}

func (a *KnownAdminAPI) UpdateGlobalSettings(ctx context.Context, req *adminv1.UpdateGlobalSettingsRequest) (*adminv1.UpdateGlobalSettingsResponse, error) {
	if err := requireConfigSuperadmin(ctx); err != nil {
		return nil, err
	}
	category, err := normalizeGlobalSettingsCategory(ctx, req.GetCategory())
	if err != nil {
		return nil, err
	}
	if len(req.GetUpdates()) == 0 {
		return nil, errs.InvalidArgument(ctx).WithMessage("updates are required")
	}
	if err := preflightGlobalSettingUpdates(ctx, req.GetUpdates()); err != nil {
		return nil, err
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}
	actor := globalSettingActor(ctx)
	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to begin transaction")
	}
	defer func() { _ = tx.Rollback() }()

	for _, item := range req.GetUpdates() {
		settingKey := strings.TrimSpace(item.GetSettingKey())
		updateValue, updateDescription, maskErr := globalSettingUpdateFields(ctx, item)
		if maskErr != nil {
			return nil, maskErr
		}
		existing, queryErr := tx.GlobalSettings.Query().
			Where(globalsettings.CategoryEQ(category), globalsettings.SettingKeyEQ(settingKey)).
			Only(ctx)
		if queryErr != nil && !lion.IsNotFound(queryErr) {
			return nil, errs.Internal(ctx).WithMessage("failed to query global setting")
		}

		spec, builtIn := lookupGlobalSettingSpec(category, settingKey)
		if builtIn {
			if updateDescription {
				return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("description is immutable for built-in setting %s", settingKey))
			}
			normalizedValue, normalizeErr := normalizeGlobalSettingValue(ctx, settingKey, item.GetSettingValue(), spec)
			if normalizeErr != nil {
				return nil, normalizeErr
			}
			if lion.IsNotFound(queryErr) {
				create := tx.GlobalSettings.Create().
					SetCategory(category).
					SetSettingKey(settingKey).
					SetSettingValue(normalizedValue).
					SetValueType(string(spec.ValueType)).
					SetDescription(spec.Description).
					SetProtected(true)
				if actor != 0 {
					create = create.SetCreatedBy(actor).SetUpdatedBy(actor)
				}
				if _, createErr := create.Save(ctx); createErr != nil {
					return nil, errs.Internal(ctx).WithMessage("failed to create built-in global setting")
				}
				continue
			}
			update := tx.GlobalSettings.Update().
				Where(globalsettings.IDEQ(existing.ID)).
				SetSettingValue(normalizedValue).
				SetValueType(string(spec.ValueType)).
				SetDescription(spec.Description).
				SetProtected(true)
			if actor != 0 {
				update = update.SetUpdatedBy(actor)
			}
			if _, updateErr := update.Save(ctx); updateErr != nil {
				return nil, errs.Internal(ctx).WithMessage("failed to update built-in global setting")
			}
			continue
		}

		if lion.IsNotFound(queryErr) {
			return nil, errs.NotFound(ctx).WithMessage(fmt.Sprintf("global setting %q not found", settingKey))
		}
		valueType := globalSettingValueType(existing.ValueType)
		if !isSupportedGlobalSettingValueType(valueType) {
			return nil, errs.FailedPrecondition(ctx).WithMessage(fmt.Sprintf("global setting %q has an unsupported value_type and can only be deleted", settingKey))
		}
		update := tx.GlobalSettings.Update().
			Where(globalsettings.IDEQ(existing.ID)).
			SetProtected(false)
		if updateValue {
			normalizedValue, normalizeErr := normalizeGlobalSettingValue(ctx, settingKey, item.GetSettingValue(), globalSettingSpec{ValueType: valueType})
			if normalizeErr != nil {
				return nil, normalizeErr
			}
			update = update.SetSettingValue(normalizedValue)
		}
		if updateDescription {
			description := strings.TrimSpace(item.GetDescription())
			if descriptionErr := validateGlobalSettingDescription(ctx, description); descriptionErr != nil {
				return nil, descriptionErr
			}
			update = update.SetDescription(description)
		}
		if actor != 0 {
			update = update.SetUpdatedBy(actor)
		}
		if _, updateErr := update.Save(ctx); updateErr != nil {
			return nil, errs.Internal(ctx).WithMessage("failed to update custom global setting")
		}
	}

	if err := tx.Commit(); err != nil {
		for _, item := range req.GetUpdates() {
			a.auditGlobalSettingMutation("update", category, strings.TrimSpace(item.GetSettingKey()), actor, "failed")
		}
		return nil, errs.Internal(ctx).WithMessage("failed to commit global settings update")
	}
	for _, item := range req.GetUpdates() {
		a.auditGlobalSettingMutation("update", category, strings.TrimSpace(item.GetSettingKey()), actor, "success")
	}

	categoryResp, err := a.buildGlobalSettingCategory(ctx, category)
	if err != nil {
		return nil, err
	}
	return &adminv1.UpdateGlobalSettingsResponse{Category: categoryResp}, nil
}

func (a *KnownAdminAPI) DeleteGlobalSetting(ctx context.Context, req *adminv1.DeleteGlobalSettingRequest) (*emptypb.Empty, error) {
	if err := requireConfigSuperadmin(ctx); err != nil {
		return nil, err
	}
	category, err := normalizeGlobalSettingsCategory(ctx, req.GetCategory())
	if err != nil {
		return nil, err
	}
	settingKey := strings.TrimSpace(req.GetSettingKey())
	if settingKey == "" {
		return nil, errs.InvalidArgument(ctx).WithMessage("setting_key is required")
	}
	if _, builtIn := lookupGlobalSettingSpec(category, settingKey); builtIn {
		return nil, errs.FailedPrecondition(ctx).WithMessage("built-in global settings cannot be deleted")
	}

	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}
	existing, err := db.GlobalSettings.Query().
		Where(globalsettings.CategoryEQ(category), globalsettings.SettingKeyEQ(settingKey)).
		Only(ctx)
	if lion.IsNotFound(err) {
		return nil, errs.NotFound(ctx).WithMessage(fmt.Sprintf("global setting %q not found", settingKey))
	}
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to query global setting")
	}
	actor := globalSettingActor(ctx)
	if _, err := db.GlobalSettings.Delete().Where(globalsettings.IDEQ(existing.ID)).Exec(ctx); err != nil {
		a.auditGlobalSettingMutation("delete", category, settingKey, actor, "failed")
		return nil, errs.Internal(ctx).WithMessage("failed to delete global setting")
	}
	a.auditGlobalSettingMutation("delete", category, settingKey, actor, "success")
	return &emptypb.Empty{}, nil
}

func requireConfigSuperadmin(ctx context.Context) error {
	if !hasSuperadminMenuAccess(ctx) {
		return errs.PermissionDenied(ctx).WithMessage("superadmin role is required to access configuration")
	}
	return nil
}

func normalizeGlobalSettingsCategory(ctx context.Context, category string) (string, error) {
	category = strings.TrimSpace(category)
	if category == "" {
		return "", errs.InvalidArgument(ctx).WithMessage("category is required")
	}
	if !isGlobalSettingsCategory(category) {
		return "", errs.InvalidArgument(ctx).WithMessage("unknown category")
	}
	return category, nil
}

func preflightGlobalSettingUpdates(ctx context.Context, updates []*adminv1.UpdateGlobalSetting) error {
	seen := make(map[string]struct{}, len(updates))
	for _, update := range updates {
		settingKey := strings.TrimSpace(update.GetSettingKey())
		if err := validateGlobalSettingKeyFormat(ctx, settingKey); err != nil {
			return err
		}
		if _, exists := seen[settingKey]; exists {
			return errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("duplicate setting_key: %s", settingKey))
		}
		seen[settingKey] = struct{}{}
		if _, _, err := globalSettingUpdateFields(ctx, update); err != nil {
			return err
		}
	}
	return nil
}

func globalSettingUpdateFields(ctx context.Context, update *adminv1.UpdateGlobalSetting) (updateValue, updateDescription bool, err error) {
	paths := update.GetUpdateMask().GetPaths()
	if len(paths) == 0 {
		return true, false, nil
	}
	for _, path := range paths {
		switch path {
		case "setting_value":
			updateValue = true
		case "description":
			updateDescription = true
		default:
			return false, false, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("unsupported update_mask path: %s", path))
		}
	}
	return updateValue, updateDescription, nil
}

func (a *KnownAdminAPI) buildGlobalSettingCategory(ctx context.Context, category string) (*adminv1.GlobalSettingCategory, error) {
	if !isGlobalSettingsCategory(category) {
		return nil, errs.InvalidArgument(ctx).WithMessage("unknown category")
	}
	db, err := a.GetLionClient()
	if err != nil {
		return nil, errs.Unimplemented(ctx).WithMessage("get lion client failed")
	}
	rows, err := db.GlobalSettings.Query().Where(globalsettings.CategoryEQ(category)).All(ctx)
	if err != nil {
		return nil, errs.Internal(ctx).WithMessage("failed to list global settings")
	}

	specs := globalSettingRegistry[category]
	rowByKey := make(map[string]*lion.GlobalSettings, len(rows))
	for _, row := range rows {
		rowByKey[row.SettingKey] = row
	}
	builtInKeys := make([]string, 0, len(specs))
	for settingKey := range specs {
		builtInKeys = append(builtInKeys, settingKey)
	}
	slices.Sort(builtInKeys)
	customKeys := make([]string, 0, len(rows))
	for _, row := range rows {
		if _, builtIn := specs[row.SettingKey]; !builtIn {
			customKeys = append(customKeys, row.SettingKey)
		}
	}
	slices.Sort(customKeys)

	result := &adminv1.GlobalSettingCategory{
		Category: category,
		Settings: make([]*adminv1.GlobalSetting, 0, len(builtInKeys)+len(customKeys)),
	}
	for _, settingKey := range builtInKeys {
		spec := specs[settingKey]
		row, exists := rowByKey[settingKey]
		if !exists {
			result.Settings = append(result.Settings, &adminv1.GlobalSetting{
				Category:     category,
				SettingKey:   settingKey,
				SettingValue: spec.DefaultValue,
				ValueType:    string(spec.ValueType),
				Description:  spec.Description,
				Protected:    true,
			})
			continue
		}
		item := toProtoGlobalSetting(row, true)
		item.Category = category
		item.SettingKey = settingKey
		item.ValueType = string(spec.ValueType)
		item.Description = spec.Description
		result.Settings = append(result.Settings, item)
	}
	for _, settingKey := range customKeys {
		row := rowByKey[settingKey]
		valueType := globalSettingValueType(row.ValueType)
		if !isSupportedGlobalSettingValueType(valueType) {
			a.logCorruptGlobalSetting(category, settingKey, "unsupported value_type")
		} else if _, validationErr := normalizeGlobalSettingValue(ctx, settingKey, row.SettingValue, globalSettingSpec{ValueType: valueType}); validationErr != nil {
			a.logCorruptGlobalSetting(category, settingKey, "invalid stored value")
		}
		result.Settings = append(result.Settings, toProtoGlobalSetting(row, false))
	}
	return result, nil
}

func toProtoGlobalSetting(row *lion.GlobalSettings, protected bool) *adminv1.GlobalSetting {
	result := &adminv1.GlobalSetting{
		Id:           int64(row.ID),
		Category:     row.Category,
		SettingKey:   row.SettingKey,
		SettingValue: row.SettingValue,
		ValueType:    row.ValueType,
		Description:  row.Description,
		Protected:    protected,
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

func globalSettingActor(ctx context.Context) int64 {
	actor, err := GetUserID(ctx)
	if err != nil {
		return 0
	}
	return actor
}

func (a *KnownAdminAPI) auditGlobalSettingMutation(action, category, settingKey string, actor int64, result string) {
	if a == nil || a.logger == nil {
		return
	}
	a.logger.
		WithField("action", action).
		WithField("category", category).
		WithField("setting_key", settingKey).
		WithField("actor", actor).
		WithField("result", result).
		Info("global setting mutation")
}

func (a *KnownAdminAPI) logCorruptGlobalSetting(category, settingKey, reason string) {
	if a == nil || a.logger == nil {
		return
	}
	a.logger.
		WithField("category", category).
		WithField("setting_key", settingKey).
		WithField("reason", reason).
		Warn("invalid stored global setting")
}
