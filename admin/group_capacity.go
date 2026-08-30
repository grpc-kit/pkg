package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/globalsettings"
	"github.com/grpc-kit/pkg/lion/groups"
)

const (
	groupCapacitySettingCategory = "internal"
	groupCapacitySettingKey      = "group-rule-capacity-lock"
)

func ensureGroupCapacitySetting(ctx context.Context, tx *lion.Tx) error {
	row, err := tx.GlobalSettings.Query().Where(
		globalsettings.CategoryEQ(groupCapacitySettingCategory),
		globalsettings.SettingKeyEQ(groupCapacitySettingKey),
	).Only(ctx)
	if lion.IsNotFound(err) {
		_, err = tx.GlobalSettings.Create().
			SetCategory(groupCapacitySettingCategory).
			SetSettingKey(groupCapacitySettingKey).
			SetSettingValue("256").
			SetValueType("int").
			SetDescription("Serialization row for active rule-group capacity checks").
			SetProtected(true).
			Save(ctx)
		return err
	}
	if err != nil {
		return err
	}
	_, err = tx.GlobalSettings.Update().Where(globalsettings.IDEQ(row.ID)).
		SetSettingValue("256").
		SetProtected(true).
		Save(ctx)
	return err
}

func lockAndCheckActiveRuleGroupCapacity(ctx context.Context, tx *lion.Tx, additional int) error {
	if err := lockActiveRuleGroupCapacity(ctx, tx); err != nil {
		return err
	}
	return checkActiveRuleGroupCapacity(ctx, tx, additional)
}

func lockActiveRuleGroupCapacity(ctx context.Context, tx *lion.Tx) error {
	row, err := tx.GlobalSettings.Query().Where(
		globalsettings.CategoryEQ(groupCapacitySettingCategory),
		globalsettings.SettingKeyEQ(groupCapacitySettingKey),
	).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return errs.FailedPrecondition(ctx).WithMessage("group capacity setting is missing; run database initialize")
		}
		return err
	}
	if _, err := tx.GlobalSettings.Update().Where(globalsettings.IDEQ(row.ID)).SetUpdatedAt(row.UpdatedAt).Save(ctx); err != nil {
		return err
	}
	return nil
}

func checkActiveRuleGroupCapacity(ctx context.Context, tx *lion.Tx, additional int) error {
	count, err := tx.Groups.Query().Where(
		groups.GroupTypeIn(int(adminv1.Group_DYNAMIC), int(adminv1.Group_SYSTEM)),
		groups.GroupStatusEQ(int(adminv1.Group_ACTIVE)),
		groups.DeletedAtIsNil(),
	).Count(ctx)
	if err != nil {
		return err
	}
	if count+additional > activeRuleGroupMax {
		return errs.ResourceExhausted(ctx).WithMessage("active DYNAMIC/SYSTEM group limit exceeded")
	}
	return nil
}
