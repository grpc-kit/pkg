package cfg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"reflect"

	"github.com/redis/go-redis/v9"
	"k8s.io/utils/lru"
)

// LRUCachebox 缓存实现 lru 效果
type LRUCachebox interface {
	GetAnyValue(ctx context.Context, key string, ptx any) bool
	SetValue(ctx context.Context, key string, value any) error
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
func (c memoryCache) GetAnyValue(ctx context.Context, key string, ptx any) bool {
	x, ok := c.cache.Get(key)
	if !ok {
		return false
	}

	// 类型检查和断言
	valType := reflect.TypeOf(ptx)
	if valType.Kind() != reflect.Ptr {
		return false
	}

	// 确保反序列化到结构体指针
	ptxVal := reflect.ValueOf(ptx).Elem()
	cachedVal := reflect.ValueOf(x)

	if !cachedVal.Type().AssignableTo(ptxVal.Type()) {
		return false
	}

	ptxVal.Set(cachedVal)

	return true
}

// SetValue 添加缓存
func (c memoryCache) SetValue(ctx context.Context, key string, value any) error {
	c.cache.Add(key, value)
	return nil
}

// GetAnyValue 获取缓存值，以 any 类型返回
func (c redisCache) GetAnyValue(ctx context.Context, key string, ptx any) bool {
	val, err := c.cache.Get(ctx, key).Result()
	if err != nil {
		return false
	}

	data, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		fmt.Println("base64 decode err: ", err.Error())
		return false
	}

	gob.Register(reflect.TypeOf(ptx).Elem())

	decoder := gob.NewDecoder(bytes.NewReader(data))
	err = decoder.Decode(ptx)
	if err != nil {
		fmt.Println("base64 decode err: ", err.Error())
		return false
	}

	return true
}

// SetValue 添加缓存
func (c redisCache) SetValue(ctx context.Context, key string, value any) error {
	var buffer bytes.Buffer
	encoder := gob.NewEncoder(&buffer)
	err := encoder.Encode(value)
	if err != nil {
		return err
	}

	return c.cache.Set(ctx, key, base64.StdEncoding.EncodeToString(buffer.Bytes()), 0).Err()
}
