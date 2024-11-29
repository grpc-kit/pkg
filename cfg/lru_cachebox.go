package cfg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"reflect"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"k8s.io/utils/lru"
)

// LRUCachebox 缓存实现 LRU 效果
type LRUCachebox interface {
	GetStructValue(ctx context.Context, key string, ptx any) bool
	SetValue(ctx context.Context, key string, value any) error
}

// memory 实现
type memoryCache struct {
	logger *logrus.Entry
	cache  *lru.Cache
}

// redis 缓存实现
type redisCache struct {
	logger *logrus.Entry
	cache  *redis.Client
}

// NewMemoryCache 创建内存缓存实例
func newMemoryCache(logger *logrus.Entry, size int) *memoryCache {
	// size 限制缓存条目数量，为 0 则不限制
	return &memoryCache{logger: logger, cache: lru.New(size)}
}

// NewRedisCache 创建 Redis 缓存实例
func newRedisCache(logger *logrus.Entry, client *redis.Client) *redisCache {
	return &redisCache{logger: logger, cache: client}
}

// GetStructValue 从内存缓存获取值，并填充用户给定的类型
func (c *memoryCache) GetStructValue(ctx context.Context, key string, ptr any) bool {
	val, ok := c.cache.Get(key)
	if !ok || !isPointer(ptr) {
		return false
	}

	ptrVal := reflect.ValueOf(ptr).Elem()
	valReflect := reflect.ValueOf(val)

	if !valReflect.Type().AssignableTo(ptrVal.Type()) {
		return false
	}

	ptrVal.Set(valReflect)
	return true
}

// SetValue 向内存缓存添加值
func (c *memoryCache) SetValue(ctx context.Context, key string, value any) error {
	c.cache.Add(key, value)
	return nil
}

// GetStructValue 从 redis 缓存获取值，以 any 类型返回
func (c *redisCache) GetStructValue(ctx context.Context, key string, ptx any) bool {
	if !isPointer(ptx) {
		return false
	}

	val, err := c.cache.Get(ctx, key).Result()
	if err != nil {
		return false
	}

	data, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		c.logger.Errorf("redis cache decode error (key: %s): %v\n", key, err)
		return false
	}

	gob.Register(reflect.TypeOf(ptx).Elem())
	decoder := gob.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(ptx); err != nil {
		c.logger.Errorf("redis cache decode error (key: %s): %v\n", key, err)
		return false
	}

	return true
}

// SetValue 向 redis 缓存添加值
func (c *redisCache) SetValue(ctx context.Context, key string, value any) error {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(value); err != nil {
		return fmt.Errorf("redis cache failed to encode value for key %s: %w", key, err)
	}

	encoded := base64.StdEncoding.EncodeToString(buffer.Bytes())
	return c.cache.Set(ctx, key, encoded, 0).Err()
}

// isPointer 检查对象是否为指针
func isPointer(ptx any) bool {
	if reflect.TypeOf(ptx).Kind() != reflect.Ptr {
		return false
	}
	return true
}
