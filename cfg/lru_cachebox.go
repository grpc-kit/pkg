package cfg

import (
	"context"

	"github.com/redis/go-redis/v9"
	"k8s.io/utils/lru"
)

// LRUCachebox 缓存实现 lru 效果
type LRUCachebox interface {
	GetAnyValue(ctx context.Context, key any) (any, bool)
	SetValue(ctx context.Context, key any, value any) error
}

// 内存缓存
type memoryCache struct {
	cache *lru.Cache
}

// redis 缓存
type redisCache struct {
	cache *redis.Client
}

// GetAnyValue 获取缓存值，以 any 类型返回
func (c memoryCache) GetAnyValue(ctx context.Context, key any) (any, bool) {
	return c.cache.Get(key)
}

// SetValue 添加缓存
func (c memoryCache) SetValue(ctx context.Context, key any, value any) error {
	c.cache.Add(key, value)
	return nil
}

// GetAnyValue 获取缓存值，以 any 类型返回
func (c redisCache) GetAnyValue(ctx context.Context, key any) (any, bool) {
	tmp, ok := key.(string)
	if !ok {
		return nil, false
	}

	val, err := c.cache.Get(ctx, tmp).Result()
	if err != nil {
		return nil, false
	}

	return val, true
}

// SetValue 添加缓存
func (c redisCache) SetValue(ctx context.Context, key any, value any) error {
	return c.cache.Set(ctx, key.(string), value, 0).Err()
}
