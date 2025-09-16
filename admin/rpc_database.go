package admin

import (
	"context"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/lion/roles"
	"google.golang.org/protobuf/types/known/emptypb"
)

// CreateDatabaseInitialize xx
func (a *KnownAdminAPI) CreateDatabaseInitialize(ctx context.Context, req *adminv1.CreateDatabaseInitializeRequest) (*emptypb.Empty, error) {
	result := &emptypb.Empty{}

	// 判断角色表是否有数据，否则认为首次部署，可以初始化数据

	db, err := a.GetLionClient()
	if err != nil {
		return nil, err
	}

	if db.Roles.Query().Select(roles.FieldID).CountX(ctx) != 0 {
		return result, nil
	}

	tx, err := db.Tx(ctx)
	if err != nil {
		return nil, err
	}

	tx.Roles.CreateBulk(
		db.Roles.Create().SetName("superadmin").SetProtected(true).SetDescription("超级管理员"),
	)

	tx.Commit()

	return result, nil
}
