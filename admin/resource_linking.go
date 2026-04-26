package admin

import (
	"context"
	"fmt"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/resources"
	"github.com/grpc-kit/pkg/lion/resourcetypes"
)

func (a *KnownAdminAPI) resolveResourceTypeForLegacy(ctx context.Context, db *lion.Client, legacyType adminv1.Resource_Type) (*lion.ResourceTypes, error) {
	code := resourceTypeCodeFromLegacy(int(legacyType))
	obj, err := db.ResourceTypes.Query().Where(resourcetypes.CodeEQ(code)).Only(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return nil, errs.InvalidArgument(ctx).WithMessage(fmt.Sprintf("resource type %s not found", code))
		}
		return nil, err
	}
	return obj, nil
}

func (a *KnownAdminAPI) resolveMenuParentResourceID(ctx context.Context, db *lion.Client, parentMenuID int64) (int64, error) {
	if parentMenuID > 0 {
		parentMenu, err := db.Menus.Get(ctx, int(parentMenuID))
		if err != nil {
			if lion.IsNotFound(err) {
				return 0, errs.InvalidArgument(ctx).WithMessage("parent menu not found")
			}
			return 0, err
		}
		if parentMenu.ResourceID == nil || *parentMenu.ResourceID == 0 {
			return 0, errs.InvalidArgument(ctx).WithMessage("parent menu resource anchor not found")
		}
		return int64(*parentMenu.ResourceID), nil
	}

	rootResource, err := db.Resources.Query().Where(
		resources.ParentIDEQ(0),
		resources.Or(
			resources.ResourceTypeCodeEQ("sys_menu"),
			resources.ResourceTypeEQ(int(adminv1.Resource_MENU.Number())),
		),
	).Order(lion.Asc(resources.FieldID)).First(ctx)
	if err != nil {
		if lion.IsNotFound(err) {
			return 0, errs.InvalidArgument(ctx).WithMessage("menu root resource not found")
		}
		return 0, err
	}
	return int64(rootResource.ID), nil
}

func (a *KnownAdminAPI) upsertMenuAnchorResource(ctx context.Context, db *lion.Client, menu *adminv1.Menu, userID int64, existingResourceID int64) (int64, error) {
	resourceType, err := a.resolveResourceTypeForLegacy(ctx, db, adminv1.Resource_MENU)
	if err != nil {
		return 0, err
	}

	parentResourceID, err := a.resolveMenuParentResourceID(ctx, db, menu.ParentId)
	if err != nil {
		return 0, err
	}

	serviceCode := a.defaultServiceCode()
	if resourceType.ServiceCode != "" {
		serviceCode = resourceType.ServiceCode
	}
	resourcePath := normalizeResourcePath("", menu.Code, menu.RoutePath)
	grn := buildResourceGRN(serviceCode, "", "", resourceType.Code, resourcePath, "")
	resourceStatus := int(adminv1.Resource_ENABLED.Number())
	resourceVisibility := int(menu.Visibility)
	resourceBuilder := func(update *lion.ResourcesUpdateOne) {
		update.SetParentID(parentResourceID)
		update.SetCode(menu.Code)
		update.SetName(grn)
		update.SetDisplayName(menu.DisplayName)
		update.SetResourceType(int(adminv1.Resource_MENU.Number()))
		update.SetResourceTypeID(resourceType.ID)
		update.SetResourceTypeCode(resourceType.Code)
		update.SetServiceCode(serviceCode)
		update.SetResourcePath(resourcePath)
		update.SetGrn(grn)
		update.SetResourceStatus(resourceStatus)
		update.SetResourceStatusCode("active")
		update.SetVisibility(resourceVisibility)
		update.SetSortOrder(int(menu.SortOrder))
		update.SetLocator(menu.RoutePath)
		update.SetVisual(menu.Icon)
		update.SetManifest(menu.Component)
		update.SetDescription(menu.Description)
		update.SetUpdatedBy(userID)
	}

	if existingResourceID > 0 {
		obj, err := db.Resources.Get(ctx, int(existingResourceID))
		if err != nil {
			return 0, err
		}
		update := obj.Update()
		resourceBuilder(update)
		saved, err := update.Save(ctx)
		if err != nil {
			return 0, err
		}
		return int64(saved.ID), nil
	}

	if menu.ResourceId > 0 {
		obj, err := db.Resources.Get(ctx, int(menu.ResourceId))
		if err != nil {
			if lion.IsNotFound(err) {
				return 0, errs.InvalidArgument(ctx).WithMessage("resource not found")
			}
			return 0, err
		}
		update := obj.Update()
		resourceBuilder(update)
		saved, err := update.Save(ctx)
		if err != nil {
			return 0, err
		}
		return int64(saved.ID), nil
	}

	if existing, err := db.Resources.Query().Where(resources.CodeEQ(menu.Code)).Only(ctx); err == nil {
		update := existing.Update()
		resourceBuilder(update)
		saved, saveErr := update.Save(ctx)
		if saveErr != nil {
			return 0, saveErr
		}
		return int64(saved.ID), nil
	} else if !lion.IsNotFound(err) {
		return 0, err
	}

	create := db.Resources.Create().
		SetParentID(parentResourceID).
		SetCode(menu.Code).
		SetName(grn).
		SetDisplayName(menu.DisplayName).
		SetResourceType(int(adminv1.Resource_MENU.Number())).
		SetResourceTypeID(resourceType.ID).
		SetResourceTypeCode(resourceType.Code).
		SetServiceCode(serviceCode).
		SetResourcePath(resourcePath).
		SetGrn(grn).
		SetResourceStatus(resourceStatus).
		SetResourceStatusCode("active").
		SetVisibility(resourceVisibility).
		SetSortOrder(int(menu.SortOrder)).
		SetLocator(menu.RoutePath).
		SetVisual(menu.Icon).
		SetManifest(menu.Component).
		SetDescription(menu.Description).
		SetCreatedBy(userID).
		SetUpdatedBy(userID)
	saved, err := create.Save(ctx)
	if err != nil {
		return 0, err
	}
	return int64(saved.ID), nil
}
