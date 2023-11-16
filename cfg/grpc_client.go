package cfg

import (
	"fmt"

	"github.com/grpc-kit/pkg/rpc"
)

// InitRPCConfig 用于初始化rpc客户端、服务端配置
func (c *LocalConfig) InitRPCConfig() error {
	r := rpc.NewConfig(c.logger)

	r.Authority = c.Services.Namespace
	r.APIEndpoint = c.Services.APIEndpoint

	r.GRPCAddress = c.Services.GRPCAddress
	if c.Services.GRPCService != nil && c.Services.GRPCService.Address != "" {
		r.GRPCAddress = c.Services.GRPCService.Address
	}

	r.HTTPAddress = c.Services.HTTPAddress
	if c.Services.HTTPService != nil && c.Services.HTTPService.Address != "" {
		r.HTTPAddress = c.Services.HTTPService.Address
	}

	if c.Services.HTTPService != nil && c.Services.HTTPService.TLSServer != nil {
		r.TLS.HTTPCertFile = c.Services.HTTPService.TLSServer.CertFile
		r.TLS.HTTPKeyFile = c.Services.HTTPService.TLSServer.KeyFile
	}
	if c.Services.HTTPService != nil && c.Services.HTTPService.TLSAuto != nil && c.Services.HTTPService.TLSAuto.ACME != nil {
		r.TLS.ACMEEmail = c.Services.HTTPService.TLSAuto.ACME.Email
		r.TLS.ACMECacheDir = c.Services.HTTPService.TLSAuto.ACME.CacheDir
		r.TLS.ACMEDomains = c.Services.HTTPService.TLSAuto.ACME.Domains
		r.TLS.ACMEServer = c.Services.HTTPService.TLSAuto.ACME.Server
	}

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
