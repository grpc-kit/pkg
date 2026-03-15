package admin

import (
	"context"
	"encoding/json"
	"fmt"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/rpc"
)

// I18NName 用于获取 i18n name
func I18NName(name string) string {
	return name
}

func MetadataJSON(metadata map[string]string) string {
	if metadata == nil {
		return ""
	}

	rawBody, err := json.Marshal(metadata)
	if err != nil {
		return ""
	}

	return string(rawBody)
}

func MetadataParse(rawBody string) map[string]string {
	result := map[string]string{}

	if rawBody == "" {
		return result
	}

	_ = json.Unmarshal([]byte(rawBody), &result)

	return result
}

// GetUserID 获取用户 ID
func GetUserID(ctx context.Context) (int64, error) {
	userID, ok := rpc.GetUserIDFromContext(ctx)
	if !ok {
		return 0, fmt.Errorf("not found user id")
	}

	return userID, nil
}

// GetPageSize 实现分页参数获取
func GetPageSize(ctx context.Context, pageSize int32) int32 {
	return GetPageSizeByStructure(ctx, pageSize, adminv1.Structure_STRUCTURE_FLAT)
}

// GetPageSizeByStructure 根据 Structure 返回分页参数
func GetPageSizeByStructure(ctx context.Context, pageSize int32, structure adminv1.Structure) int32 {
	defaultPageSize := int32(20)
	maxPageSize := int32(100)

	switch structure {
	case adminv1.Structure_STRUCTURE_TREE, adminv1.Structure_STRUCTURE_TREE_EXPANDED:
		defaultPageSize = 1000
		maxPageSize = 5000
	}

	currentPageSize := pageSize

	if currentPageSize <= 0 {
		currentPageSize = defaultPageSize
	}
	if currentPageSize > maxPageSize {
		currentPageSize = maxPageSize
	}

	return currentPageSize
}
