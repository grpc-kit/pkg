package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion/roles"
)

// ListRoles 创建用户
func (a *KnownAdminAPI) ListRoles(ctx context.Context, req *adminv1.ListRolesRequest) (*adminv1.ListRolesResponse, error) {
	result := &adminv1.ListRolesResponse{}

	rl, err := a.config.db.Roles.Query().
		Select(roles.FieldID, roles.FieldName, roles.FieldDescription).
		All(ctx)
	if err != nil {
		return nil, err
	}

	for _, r := range rl {
		result.Roles = append(result.Roles, &adminv1.Role{
			Id:          int32(r.ID),
			Name:        r.Name,
			Description: r.Description,
		})
	}

	return result, nil
}
