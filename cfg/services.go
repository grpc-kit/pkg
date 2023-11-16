package cfg

import (
	"fmt"
	"strconv"
	"strings"
)

// HTTPService 用于 HTTP 服务配置
type HTTPService struct {
	Enabled   *bool          `mapstructure:"enabled"`
	Address   string         `mapstructure:"address"`
	TLSAuto   *TLSAutoConfig `mapstructure:"tls_auto"`
	TLSServer *TLSConfig     `mapstructure:"tls_server"`
	TLSClient *TLSConfig     `mapstructure:"tls_client"`
}

// GRPCService 用于 gRPC 服务配置
type GRPCService struct {
	Enabled   *bool      `mapstructure:"enabled"`
	Address   string     `mapstructure:"address"`
	TLSServer *TLSConfig `mapstructure:"tls_server"`
}

// TLSAutoConfig 用于证书的自动化生成
type TLSAutoConfig struct {
	ACME *struct {
		Server   string   `mapstructure:"server"`
		Email    string   `mapstructure:"email"`
		Domains  []string `mapstructure:"domains"`
		CacheDir string   `mapstructure:"cache_dir"`
	} `mapstructure:"acme"`

	SPIFFE *struct {
		Agent string `mapstructure:"agent"`
	}
}

// getGRPCListenHostPort 解析gRPC监听的IP地址与端口
func (s ServicesConfig) getGRPCListenHostPort() (string, int, error) {
	grpcAddress := s.GRPCAddress
	if s.GRPCService != nil && s.GRPCService.Address != "" {
		grpcAddress = s.GRPCService.Address
	}

	temps := strings.Split(grpcAddress, ":")
	if len(temps) != 2 {
		return "", -1, fmt.Errorf("grpc-address format invalid")
	}

	port, err := strconv.Atoi(temps[1])
	if err != nil {
		return "", -1, fmt.Errorf("grpc-address format invalid")
	}

	return temps[0], port, nil
}

// getGRPCListenPort 本地配置中gRPC监听的端口
func (s ServicesConfig) getGRPCListenPort() int {
	_, port, _ := s.getGRPCListenHostPort()
	return port
}
