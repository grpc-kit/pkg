package cfg

import (
	"fmt"
)

// CacheboxConfig 缓存配置，区别于数据库配置，缓存的数据可以丢失
type CacheboxConfig struct {
	lruCache LRUCachebox

	// 全局是否启用
	Enable bool `mapstructure:"enable"`
	// 使用的驱动类型
	Driver string `mapstructure:"driver"`
	// MemoryCacheboxConfig 内存缓存配置
	Memory MemoryCacheboxConfig `mapstructure:"memory"`
	// RedisCacheboxConfig redis 缓存配置
	Redis RedisCacheboxConfig `mapstructure:"redis"`
}

// MemoryCacheboxConfig 内存缓存配置
type MemoryCacheboxConfig struct {
	// 最大缓存条数，超过了会进行驱逐，默认无限制
	MaxEntry int `mapstructure:"max_entry"`
}

// RedisCacheboxConfig redis 缓存配置
type RedisCacheboxConfig struct {
	Endpoints []string `mapstructure:"endpoints"`
	Username  string   `mapstructure:"username"`
	Password  string   `mapstructure:"password"`
	DBNumber  int      `mapstructure:"db_number"`
	Sentinel  struct {
		MasterName string `mapstructure:"master_name"`
		Username   string `mapstructure:"username"`
		Password   string `mapstructure:"password"`
	} `mapstructure:"sentinel"`
	TLSClientConfig *TLSConfig `mapstructure:"tls_client_config"`
}

func (c *LocalConfig) initCachebox() error {
	if c.Cachebox == nil {
		c.Cachebox = &CacheboxConfig{
			Enable: false,
		}
	}

	if !c.Cachebox.Enable {
		return nil
	}

	c.Cachebox.defaultValues()

	switch c.Cachebox.Driver {
	case "memory":
		c.Cachebox.lruCache = newMemoryCache(c.logger, c.Cachebox.Memory.MaxEntry)
	case "redis":
		c.Cachebox.lruCache = newRedisCache(c.logger, c.Cachebox.Redis)
	default:
		return fmt.Errorf("cachebox driver [%s] not found", c.Cachebox.Driver)
	}

	return nil
}

func (c *CacheboxConfig) defaultValues() {
	return
}
