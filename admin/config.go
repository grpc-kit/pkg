package admin

import (
	"github.com/grpc-kit/pkg/lion"
	"github.com/sirupsen/logrus"
)

// config 配置信息
type config struct {
	logger *logrus.Entry
	db     *lion.Client

	prefix string // 接口前缀

	// oidc 认证域名
	provider string
	// oidc 客户端ID
	clientID string
	// oidc 客户端密钥
	clientSecret string
}

// Options xx
type Options func(c *config)

// WithLogger 返回一个 AdminAPIOption，用于设置 AdminAPI 的日志记录器。
// 参数 logger 是一个指向 logrus.Entry 的指针，表示要使用的日志记录器。
// 返回值是一个 AdminAPIOption，用于配置 AdminAPI 的日志记录器。
func WithLogger(logger *logrus.Entry) Options {
	return func(c *config) {
		c.logger = logger
	}
}

func WithLionClient(client *lion.Client) Options {
	return func(c *config) {
		c.db = client
	}
}

func WithPrefix(prefix string) Options {
	return func(c *config) {
		c.prefix = prefix
	}
}

func WithOIDCProvider(provider, clientID, clientSecret string) Options {
	return func(c *config) {
		c.provider = provider
		c.clientID = clientID
		c.clientSecret = clientSecret
	}
}
