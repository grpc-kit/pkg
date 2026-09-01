package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/departments"
	"github.com/grpc-kit/pkg/lion/roles"
)

type storedUserFilterConfig struct {
	UserFilter string `json:"user_filter"`
}

type validatedGroupConfig struct {
	sourceID *int
	config   json.RawMessage
}

type groupReferenceError struct{ message string }

func (e *groupReferenceError) Error() string { return e.message }

func groupConfigWriteError(ctx context.Context, err error) error {
	var referenceErr *groupReferenceError
	if errors.As(err, &referenceErr) {
		return errs.FailedPrecondition(ctx).WithMessage(referenceErr.Error())
	}
	return errs.InvalidArgument(ctx).WithMessage(err.Error())
}

func validateGroupTypeConfig(ctx context.Context, db *lion.Client, group *adminv1.Group, allowSystem bool) (*validatedGroupConfig, error) {
	if group == nil {
		return nil, fmt.Errorf("group is required")
	}
	if group.ParentId != 0 {
		return nil, fmt.Errorf("parent_id must be 0 until group hierarchy is enabled")
	}
	if group.MaxMembers < 0 {
		return nil, fmt.Errorf("max_members must be greater than or equal to 0")
	}
	result := &validatedGroupConfig{}
	switch group.Type {
	case adminv1.Group_TYPE_UNSPECIFIED:
		return nil, fmt.Errorf("group type must be specified")
	case adminv1.Group_DEPARTMENT:
		config := group.GetDepartmentConfig()
		if config == nil || config.DepartmentId <= 0 {
			return nil, fmt.Errorf("department_config.department_id is required")
		}
		if group.MaxMembers != 0 {
			return nil, fmt.Errorf("DEPARTMENT groups require max_members=0")
		}
		if err := requireActiveDepartmentGroupReference(ctx, db, int(config.DepartmentId)); err != nil {
			return nil, err
		}
		value := int(config.DepartmentId)
		result.sourceID = &value
	case adminv1.Group_ROLE:
		config := group.GetRoleConfig()
		if config == nil || config.RoleId <= 0 {
			return nil, fmt.Errorf("role_config.role_id is required")
		}
		if group.MaxMembers != 0 {
			return nil, fmt.Errorf("ROLE groups require max_members=0")
		}
		exists, err := db.Roles.Query().Where(
			roles.IDEQ(int(config.RoleId)),
			roles.RoleStatusEQ(int(adminv1.Role_ACTIVE)),
			roles.DeletedAtIsNil(),
		).Exist(ctx)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, &groupReferenceError{message: "role group reference must be active and not deleted"}
		}
		value := int(config.RoleId)
		result.sourceID = &value
	case adminv1.Group_DYNAMIC:
		config := group.GetDynamicConfig()
		if config == nil {
			return nil, fmt.Errorf("dynamic_config is required")
		}
		if group.MaxMembers != 0 {
			return nil, fmt.Errorf("DYNAMIC groups require max_members=0")
		}
		compiled, err := compileUserFilter(config.UserFilter)
		if err != nil {
			return nil, fmt.Errorf("invalid dynamic_config.user_filter: %w", err)
		}
		result.config, err = json.Marshal(storedUserFilterConfig{UserFilter: compiled.canonical})
		if err != nil {
			return nil, err
		}
	case adminv1.Group_SYSTEM:
		if !allowSystem {
			return nil, fmt.Errorf("SYSTEM groups can only be written by system seed")
		}
		config := group.GetSystemConfig()
		if config == nil {
			return nil, fmt.Errorf("system_config is required")
		}
		if group.MaxMembers != 0 {
			return nil, fmt.Errorf("SYSTEM groups require max_members=0")
		}
		compiled, err := compileUserFilter(config.UserFilter)
		if err != nil {
			return nil, fmt.Errorf("invalid system_config.user_filter: %w", err)
		}
		result.config, err = json.Marshal(storedUserFilterConfig{UserFilter: compiled.canonical})
		if err != nil {
			return nil, err
		}
	case adminv1.Group_PROJECT, adminv1.Group_EXTERNAL, adminv1.Group_COMMUNITY:
		if group.GetConfig() != nil {
			return nil, fmt.Errorf("%s groups must not contain config", group.Type.String())
		}
	default:
		return nil, fmt.Errorf("unsupported group type %d", group.Type)
	}
	return result, nil
}

func requireActiveDepartmentGroupReference(ctx context.Context, db *lion.Client, departmentID int) error {
	if departmentID <= 0 {
		return fmt.Errorf("department_config.department_id is required")
	}
	exists, err := db.Departments.Query().Where(
		departments.IDEQ(departmentID),
		departments.DepartmentStatusEQ(int(adminv1.Department_ACTIVE)),
		departments.DeletedAtIsNil(),
	).Exist(ctx)
	if err != nil {
		return err
	}
	if !exists {
		return &groupReferenceError{message: "department group reference must be active and not deleted"}
	}
	return nil
}

func decodeStoredUserFilter(raw json.RawMessage) (*compiledUserFilter, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("config is missing")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config storedUserFilterConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("invalid config JSON: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	return compileUserFilter(config.UserFilter)
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("config JSON contains trailing value")
		}
		return fmt.Errorf("invalid config JSON: %w", err)
	}
	return nil
}

func populateGroupProtoConfig(dst *adminv1.Group, src *lion.Groups) error {
	if dst == nil || src == nil {
		return fmt.Errorf("group is required")
	}
	switch adminv1.Group_Type(src.GroupType) {
	case adminv1.Group_DEPARTMENT:
		if src.SourceID == nil || *src.SourceID <= 0 || len(src.Config) != 0 {
			return fmt.Errorf("invalid DEPARTMENT group storage config")
		}
		dst.Config = &adminv1.Group_DepartmentConfig_{DepartmentConfig: &adminv1.Group_DepartmentConfig{DepartmentId: int64(*src.SourceID)}}
	case adminv1.Group_ROLE:
		if src.SourceID == nil || *src.SourceID <= 0 || len(src.Config) != 0 {
			return fmt.Errorf("invalid ROLE group storage config")
		}
		dst.Config = &adminv1.Group_RoleConfig_{RoleConfig: &adminv1.Group_RoleConfig{RoleId: int64(*src.SourceID)}}
	case adminv1.Group_DYNAMIC:
		if src.SourceID != nil {
			return fmt.Errorf("invalid DYNAMIC group source_id")
		}
		compiled, err := decodeStoredUserFilter(src.Config)
		if err != nil {
			return fmt.Errorf("invalid DYNAMIC group config: %w", err)
		}
		dst.Config = &adminv1.Group_DynamicConfig_{DynamicConfig: &adminv1.Group_DynamicConfig{UserFilter: compiled.canonical}}
	case adminv1.Group_SYSTEM:
		if src.SourceID != nil {
			return fmt.Errorf("invalid SYSTEM group source_id")
		}
		compiled, err := decodeStoredUserFilter(src.Config)
		if err != nil {
			return fmt.Errorf("invalid SYSTEM group config: %w", err)
		}
		dst.Config = &adminv1.Group_SystemConfig_{SystemConfig: &adminv1.Group_SystemConfig{UserFilter: compiled.canonical}}
	case adminv1.Group_PROJECT, adminv1.Group_EXTERNAL, adminv1.Group_COMMUNITY:
		if src.SourceID != nil || len(src.Config) != 0 {
			return fmt.Errorf("invalid %s group storage config", adminv1.Group_Type(src.GroupType))
		}
	default:
		return fmt.Errorf("invalid group type %d", src.GroupType)
	}
	return nil
}
