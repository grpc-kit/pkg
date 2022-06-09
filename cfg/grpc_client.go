package cfg

import (
	"fmt"

	"github.com/grpc-kit/pkg/rpc"
)

// InitRPCConfig 用于初始化rpc客户端、服务端配置
func (c *LocalConfig) InitRPCConfig() error {
	r := rpc.NewConfig(c.logger)

	r.Authority = c.Services.Namespace
	r.GRPCAddress = c.Services.GRPCAddress
	r.HTTPAddress = c.Services.HTTPAddress
	r.APIEndpoint = c.Services.APIEndpoint
	c.rpcConfig = r

	return nil
}

// GetRPCClient 获取rpc客户端实例，TODO;（未完善，当前主要解耦框架模版）
func (c *LocalConfig) GetRPCClient() (*rpc.Client, error) {
	if c.rpcConfig == nil {
		return nil, fmt.Errorf("rpc cconfig is nil")
	}
	return rpc.NewClient(c.rpcConfig), nil
}

// GetRPCServer 获取rpc服务端实例，TODO;（未完善，当前主要解耦框架模版）
func (c *LocalConfig) GetRPCServer() (*rpc.Server, error) {
	if c.rpcConfig == nil {
		return nil, fmt.Errorf("rpc cconfig is nil")
	}
	return rpc.NewServer(c.rpcConfig), nil
}
