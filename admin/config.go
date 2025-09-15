package admin

import (
	"github.com/grpc-kit/pkg/lion"
	"github.com/sirupsen/logrus"
)

// config 配置信息
type config struct {
	logger *logrus.Entry
	db     *lion.Client

	aesKey []byte

	// oidc 认证域名
	issuer string
	// oidc 客户端ID
	clientID string
	// oidc 客户端密钥
	clientSecret string

	// 静态用户
	staticUsers *StaticUsers
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

// WithLionClient 内置管理模块的 ent client 数据库 lion 数据结构
func WithLionClient(client *lion.Client) Options {
	return func(c *config) {
		c.db = client
	}
}

// WithOIDCProvider 设置 oidc 认证的基础信息
func WithOIDCProvider(issuer, clientID, clientSecret string) Options {
	return func(c *config) {
		c.issuer = issuer
		c.clientID = clientID
		c.clientSecret = clientSecret
	}
}

// WithAESKey 设置 AES 加密的密钥
func WithAESKey(key []byte) Options {
	return func(c *config) {
		c.aesKey = key
	}
}

// WithStaticUsers 设置本地配置的静态用户
func WithStaticUsers(users *StaticUsers) Options {
	return func(c *config) {
		c.staticUsers = users
	}
}
