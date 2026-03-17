package admin

import (
	"context"
	"fmt"

	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/roles"
	"github.com/grpc-kit/pkg/rpc"
	"github.com/sirupsen/logrus"
)

// KnownAdminAPI xx
type KnownAdminAPI struct {
	config        *config
	logger        *logrus.Entry
	mfaChallenges *mfaChallengeStore
}

// New xx
func New(opts ...Options) *KnownAdminAPI {
	c := &config{}

	for _, opt := range opts {
		opt(c)
	}

	// TODO; 默认值设置
	if c.logger == nil {
		c.logger = logrus.NewEntry(logrus.New())
	}

	return &KnownAdminAPI{
		config:        c,
		logger:        c.logger,
		mfaChallenges: newMFAChallengeStore(),
	}
}

func (a *KnownAdminAPI) GetLionClient() (*lion.Client, error) {
	if a.config == nil || a.config.db == nil {
		return nil, fmt.Errorf("not found database client")
	}

	return a.config.db, nil
}

// getUserRoleID 获取用户的角色 ID 列表
func (a *KnownAdminAPI) getUserRoleID(ctx context.Context) ([]int, error) {
	result := make([]int, 0)

	// 从 jwt 中获取用户组
	gs, ok := rpc.GetGroupsFromContext(ctx)
	if !ok {
		return result, errs.PermissionDenied(ctx).WithMessage("not found groups")
	}

	ridObj, err := a.config.db.Roles.Query().
		Select(
			roles.FieldID,
		).
		Where(
			roles.CodeIn(gs...),
		).
		All(ctx)
	if err != nil {
		return result, err
	}
	if len(ridObj) == 0 {
		return result, errs.PermissionDenied(ctx).WithMessage("user not in any role")
	}

	for _, rid := range ridObj {
		result = append(result, rid.ID)
	}

	return result, nil
}
