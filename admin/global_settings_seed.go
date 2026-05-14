package admin

import (
	"context"

	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/globalsettings"
)

func ensureGlobalSettingsSeeds(ctx context.Context, tx *lion.Tx) error {
	for category, specs := range globalSettingRegistry {
		for settingKey, spec := range specs {
			exists, err := tx.GlobalSettings.Query().
				Where(
					globalsettings.CategoryEQ(category),
					globalsettings.SettingKeyEQ(settingKey),
				).
				Exist(ctx)
			if err != nil {
				return err
			}
			if exists {
				continue
			}

			if _, err := tx.GlobalSettings.Create().
				SetCategory(category).
				SetSettingKey(settingKey).
				SetSettingValue(spec.DefaultValue).
				SetValueType(string(spec.ValueType)).
				SetDescription(spec.Description).
				SetProtected(spec.Protected).
				Save(ctx); err != nil {
				return err
			}
		}
	}

	return nil
}