package cfg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"reflect"

	"github.com/grpc-kit/pkg/vars"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"k8s.io/utils/lru"
)

// LRUCachebox 缓存实现 LRU 效果
type LRUCachebox interface {
	// Remove 重内存缓存移除值
	Remove(ctx context.Context, key string) bool
	// SetValue 向内存缓存添加值
	SetValue(ctx context.Context, key string, value any) bool
	// GetStructValue 从内存缓存获取值，并填充用户给定的类型
	GetStructValue(ctx context.Context, key string, ptx any) bool
}

// memory 实现
type memoryCache struct {
	logger *logrus.Entry
	cache  *lru.Cache
}

// redis 缓存实现
type redisCache struct {
	logger *logrus.Entry
	cache  redis.UniversalClient
}

// NewMemoryCache 创建内存缓存实例
func newMemoryCache(logger *logrus.Entry, size int) *memoryCache {
	// size 限制缓存条目数量，为 0 则不限制
	return &memoryCache{logger: logger, cache: lru.New(size)}
}

// NewRedisCache 创建 Redis 缓存实例
func newRedisCache(logger *logrus.Entry, config RedisCacheboxConfig) *redisCache {
	opt := &redis.UniversalOptions{
		ClientName:       vars.Appname,
		Addrs:            config.Endpoints,
		Username:         config.Username,
		Password:         config.Password,
		DB:               config.DBNumber,
		SentinelUsername: config.Sentinel.Username,
		SentinelPassword: config.Sentinel.Password,
		MasterName:       config.Sentinel.MasterName,
	}

	if config.TLSClientConfig != nil {
		tlsConfig, err := NewTLSConfig(config.TLSClientConfig)
		if err != nil {
			logger.Panicf("redis tls config error: %v\n", err)
		}

		opt.TLSConfig = tlsConfig
	}

	return &redisCache{logger: logger, cache: redis.NewUniversalClient(opt)}
}

// GetStructValue 从内存缓存获取值，并填充用户给定的类型
func (c *memoryCache) GetStructValue(ctx context.Context, key string, ptr any) bool {
	val, ok := c.cache.Get(getCacheKey(key))
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
func (c *memoryCache) SetValue(ctx context.Context, key string, value any) bool {
	c.cache.Add(getCacheKey(key), value)
	return true
}

// Remove 重内存缓存移除值
func (c *memoryCache) Remove(ctx context.Context, key string) bool {
	c.cache.Remove(getCacheKey(key))
	return true
}

// GetStructValue 从 redis 缓存获取值，以 any 类型返回
func (c *redisCache) GetStructValue(ctx context.Context, key string, ptr any) bool {
	if !isPointer(ptr) {
		return false
	}

	val, err := c.cache.Get(ctx, getCacheKey(key)).Result()
	if err != nil {
		return false
	}

	data, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		c.logger.Errorf("redis cache decode error (key: %s): %v\n", key, err)
		return false
	}

	// gob.Register(reflect.TypeOf(ptr).Elem())
	decoder := gob.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(ptr); err != nil {
		c.logger.Errorf("redis cache decode error (key: %s): %v\n", key, err)
		return false
	}

	return true
}

// SetValue 向 redis 缓存添加值
func (c *redisCache) SetValue(ctx context.Context, key string, value any) bool {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	if err := encoder.Encode(value); err != nil {
		c.logger.Errorf("redis cache failed to encode value for key %v: %v", key, err)
		return false
	}

	encoded := base64.StdEncoding.EncodeToString(buffer.Bytes())
	err := c.cache.Set(ctx, getCacheKey(key), encoded, 0).Err()
	if err != nil {
		c.logger.Errorf("redis cache failed to set value for key %v: %v", key, err)
		return false
	}

	return true
}

// Remove 重内存缓存移除值
func (c *redisCache) Remove(ctx context.Context, key string) bool {
	err := c.cache.Del(ctx, getCacheKey(key)).Err()
	if err != nil {
		return false
	}

	return true
}

// isPointer 检查对象是否为指针
func isPointer(ptr any) bool {
	if reflect.TypeOf(ptr).Kind() != reflect.Ptr {
		return false
	}
	return true
}

func getCacheKey(key string) string {
	appname := vars.Appname
	if appname == "" {
		appname = "grpc-kit"
	}

	return fmt.Sprintf("%v:cachebox:%v", appname, key)
}
