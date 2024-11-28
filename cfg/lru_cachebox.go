package cfg

import (
	"context"

	"k8s.io/utils/lru"
)

// LRUCachebox 缓存实现 lru 效果
type LRUCachebox struct {
	// 内存缓存
	cache *lru.Cache
}

// GetAnyValue 获取缓存值，以 any 类型返回
func (c *LRUCachebox) GetAnyValue(ctx context.Context, key any) (any, bool) {
	return c.cache.Get(key)
}

// SetValue 添加缓存
func (c *LRUCachebox) SetValue(ctx context.Context, key any, value any) error {
	c.cache.Add(key, value)
	return nil
}
