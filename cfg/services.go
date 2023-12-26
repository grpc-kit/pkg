package cfg

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
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

// getClientCredentials 用于根据配置文件获取证书配置，存在四种情况：
// 1. 如果未配置 grpc 证书，则使用 insecure.NewCredentials()
// 2. 如果配置了 grpc 服务端证书，未配置客户端 ca 则跳过 ca 验证
// 3. 如果配置了 grpc 服务端证书，客户端配置了验证用的 ca 证书，则会验证服务端证书是否有效
// 4. 如果配置了 grpc 服务端证书，客户端也配置了证书，则客户端请求时会带上证书内容，提供服务端验证客户端证书是否有效
func (s ServicesConfig) getClientCredentials() (credentials.TransportCredentials, error) {
	// 配置了 grpc 服务端证书
	if s.GRPCService != nil &&
		s.GRPCService.TLSServer != nil &&
		s.GRPCService.TLSServer.CertFile != "" &&
		s.GRPCService.TLSServer.KeyFile != "" {

		// 配置了客户端 ca 证书，需验证服务端证书合法性
		if s.HTTPService != nil &&
			s.HTTPService.TLSClient != nil &&
			s.HTTPService.TLSClient.CAFile != "" {

			caBody, err := ioutil.ReadFile(s.HTTPService.TLSClient.CAFile)
			if err != nil {
				return nil, err
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caBody) {
				return nil, fmt.Errorf("services.http_service.tls_client.ca_file: %v not valid", s.HTTPService.TLSClient.CAFile)
			}

			tlsConfig := &tls.Config{
				InsecureSkipVerify: s.HTTPService.TLSClient.InsecureSkipVerify,
				RootCAs:            caPool,
			}

			// 客户端提交证书，用于服务端验证客户端
			if s.HTTPService.TLSClient.CertFile != "" && s.HTTPService.TLSClient.KeyFile != "" {
				cert, err := tls.LoadX509KeyPair(s.HTTPService.TLSClient.CertFile, s.HTTPService.TLSClient.KeyFile)
				if err != nil {
					return nil, err
				}

				tlsConfig.Certificates = []tls.Certificate{cert}
			}

			return credentials.NewTLS(tlsConfig), nil
		} else {
			// 未配置客户端 ca 证书，跳过服务端证书验证
			return credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}), nil
		}
	}

	// 未配置 grpc 证书，则使用 insecure.NewCredentials()
	return insecure.NewCredentials(), nil
}

// 判断是否开启了 grpc 服务
func (s ServicesConfig) hasEnableGRPCServer() bool {
	if s.GRPCService == nil || s.GRPCService.Enabled == nil {
		return true
	}

	return *s.GRPCService.Enabled
}

// 判断是否开启了 http 服务
func (s ServicesConfig) hasEnableHTTPServer() bool {
	if s.HTTPService == nil || s.HTTPService.Enabled == nil {
		return true
	}

	return *s.HTTPService.Enabled
}
