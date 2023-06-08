package cfg

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// HTTPConfig 用于控制客户端通过 http 协议连接服务端的一些能力
type HTTPConfig struct {
	// 允许你自定义 TLS 配置，以满足特定的需求，例如指定根证书、跳过证书验证、设置密码套件等
	TLSClientConfig TLSConfig `mapstructure:"tls_client_config" yaml:"tls_client_config"`

	// 可以控制在建立 TLS 握手过程中等待的最大时间，客户端和服务器之间进行密钥交换和协商加密参数等操作
	// 如果在指定的超时时间内未完成握手，客户端可以终止连接或采取其他处理方式
	TLSHandshakeTimeout time.Duration `mapstructure:"tls_handshake_timeout" yaml:"tls_handshake_timeout"`

	// HTTP 的 keep-alive 是一种机制，允许客户端在单个 TCP 连接上发送多个 HTTP 请求，而无需为每个请求都建立和关闭连接
	// 是否禁用 HTTP 的 keep-alive 功能，这样每个 HTTP 请求都会使用一个新的连接，意味着每次请求都需要建立和关闭连接
	DisableKeepAlives bool `mapstructure:"disable_keep_alives" yaml:"disable_keep_alives"`

	// 如果开启则请求中不会包含 "Accept-Encoding: gzip" 的请求头，即禁止了请求压缩，这意味着即使服务端返回的响应使用了gzip压缩，Transport也不会自动解压缩响应体
	DisableCompression bool `mapstructure:"disable_compression" yaml:"disable_compression"`

	// 可以控制在空闲连接池中保持的最大连接数，超过这个数量的空闲连接将被关闭
	// 通过使用 keep-alive 机制，客户端可以在多次请求之间重用已经建立的连接，以减少每次请求的连接建立和断开的开销
	MaxIdleConns int `mapstructure:"max_idle_conns" yaml:"max_idle_conns"`

	// 可以针对每个主机控制保持的最大空闲连接数，这可以使每个主机具有独立的连接池，而不是使用全局的连接池
	// 每个主机可以独立地管理和复用空闲连接，以优化连接的使用和性能
	MaxIdleConnsPerHost int `mapstructure:"max_idle_conns_per_host" yaml:"max_idle_conns_per_host"`

	// 用于可选地限制每个主机的总连接数，包括处于拨号、活动和空闲状态的连接
	MaxConnsPerHost int `mapstructure:"max_conns_per_host" yaml:"max_conns_per_host"`

	// 空闲连接的超时时间，指定空闲连接在关闭之前保持的最长时间
	IdleConnTimeout time.Duration `mapstructure:"idle_conn_timeout" yaml:"idle_conn_timeout"`

	// 客户端在发送请求后等待服务器响应头的时间，如果在指定的超时时间内未收到响应头，客户端可以终止连接或采取其他处理方式
	ResponseHeaderTimeout time.Duration `mapstructure:"response_header_timeout" yaml:"response_header_timeout"`

	// 用于在完全发送请求头后，等待服务器首次响应头的时间
	ExpectContinueTimeout time.Duration `mapstructure:"expect_continue_timeout" yaml:"expect_continue_timeout"`

	// 可以控制接收和处理服务器响应头的大小
	// 响应头中包含了诸如状态码、响应头字段等信息，如果服务器的响应头超过了指定的最大字节数，那么将会触发一个错误，导致请求失败
	MaxResponseHeaderBytes int64 `mapstructure:"max_response_header_bytes" yaml:"max_response_header_bytes"`

	// 用于控制写缓冲区大小，它是用于临时存储要发送到传输层的数据的内存区域
	// 通过使用写缓冲区可以减少实际的写操作次数，提高写入数据的效率，较大的写缓冲区可以在一次写操作中发送更多的数据，减少了频繁的系统调用和网络开销
	// 设置为 0，则会使用默认值（目前为4KB）
	WriteBufferSize int `mapstructure:"write_buffer_size" yaml:"write_buffer_size"`

	// 用于控制读缓冲区大小，它是用于临时存储从传输层读取的数据的内存区域
	// 通过使用读缓冲区可以减少实际的读操作次数，提高从传输层读取数据的效率，较大的读缓冲区可以一次性读取更多的数据，减少了频繁的系统调用和网络开销
	// 设置为 0，则会使用默认值（目前为4KB）
	ReadBufferSize int `mapstructure:"read_buffer_size" yaml:"read_buffer_size"`

	// 在配置了 Dial、DialTLS、DialContext 函数或 TLSClientConfig 时，会禁用 HTTP/2
	// 这时可以配置开启，也会尝试使用 HTTP/2 协议进行升级，不过仍然需要确保服务器支持 HTTP/2 协议才能成功升级
	ForceAttemptHTTP2 bool `mapstructure:"force_attempt_http2" yaml:"force_attempt_http2"`
}

// TLSConfig 用于配置客户端与服务端 tls 相关行为
type TLSConfig struct {
	// 进行 TLS 握手时，客户端会检查服务器返回的证书中的主机名与客户端期望的主机名是否匹配
	// 如果设置了 ServerName，那么客户端会使用该字段的值来验证服务器证书的主机名
	// 如果设置了 InsecureSkipVerify 为 true，则跳过主机名验证
	ServerName string `mapstructure:"server_name" yaml:"server_name"`

	// 默认情况下，客户端会验证服务器的证书链和主机名，以确保建立安全的 TLS 连接，避免被中间人攻击
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify" yaml:"insecure_skip_verify"`

	// 最低支持的 tls 版本，取值范围：TLSv1 TLSv1.1 TLSv1.2 TLSv1.3
	MinVersion string `mapstructure:"min_version" yaml:"min_version"`
	// 最高支持的 tls 版本，取值范围：TLSv1 TLSv1.1 TLSv1.2 TLSv1.3
	MaxVersion string `mapstructure:"max_version" yaml:"max_version"`

	// 用于定义客户端在验证服务器证书时使用的根证书，一般在自签证书时使用
	CAFile string `mapstructure:"ca_file" yaml:"ca_file"`
	// 客户端证书公钥
	CertFile string `mapstructure:"cert_file" yaml:"cert_file"`
	// 客户端证书私钥
	KeyFile string `mapstructure:"key_file" yaml:"key_file"`
}

// NewHTTPTransport 创建默认的 http transport
func NewHTTPTransport(config HTTPConfig) (*http.Transport, error) {
	tlsConfig, err := NewTLSConfig(&config.TLSClientConfig)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: tlsConfig,
	}

	if config.TLSHandshakeTimeout.Seconds() > 0 {
		tr.TLSHandshakeTimeout = config.TLSHandshakeTimeout
	}
	if config.DisableKeepAlives {
		tr.DisableKeepAlives = true
	}
	if config.DisableCompression {
		tr.DisableCompression = true
	}
	if config.MaxIdleConns > 0 {
		tr.MaxIdleConns = config.MaxIdleConns
	}
	if config.MaxIdleConnsPerHost > 0 {
		tr.MaxIdleConnsPerHost = config.MaxIdleConnsPerHost
	}
	if config.MaxConnsPerHost > 0 {
		tr.MaxConnsPerHost = config.MaxConnsPerHost
	}
	if config.IdleConnTimeout.Seconds() > 0 {
		tr.IdleConnTimeout = config.IdleConnTimeout
	}
	if config.ResponseHeaderTimeout.Seconds() > 0 {
		tr.ResponseHeaderTimeout = config.ResponseHeaderTimeout
	}
	if config.ExpectContinueTimeout.Seconds() > 0 {
		tr.ExpectContinueTimeout = config.ExpectContinueTimeout
	}
	if config.MaxResponseHeaderBytes > 0 {
		tr.MaxResponseHeaderBytes = config.MaxResponseHeaderBytes
	}
	if config.WriteBufferSize > 0 {
		tr.WriteBufferSize = config.WriteBufferSize
	}
	if config.ReadBufferSize > 0 {
		tr.ReadBufferSize = config.ReadBufferSize
	}
	if config.ForceAttemptHTTP2 {
		tr.ForceAttemptHTTP2 = config.ForceAttemptHTTP2
	}

	// 设置默认值
	if tr.MaxIdleConns == 0 {
		tr.MaxIdleConns = 256
	}
	if tr.IdleConnTimeout.Seconds() == 0 {
		tr.IdleConnTimeout = 90 * time.Second
	}
	if tr.TLSHandshakeTimeout.Seconds() == 0 {
		tr.TLSHandshakeTimeout = 10 * time.Second
	}
	if tr.ExpectContinueTimeout.Seconds() == 0 {
		tr.ExpectContinueTimeout = 10 * time.Second
	}

	return tr, nil
}

// NewTLSConfig 根据 tls 配置初始化 tls.Config 实例
func NewTLSConfig(t *TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: t.InsecureSkipVerify}

	if v := t.getTLSVersion(t.MinVersion); v > 0 {
		tlsConfig.MinVersion = v
	}
	if v := t.getTLSVersion(t.MaxVersion); v > 0 {
		tlsConfig.MaxVersion = v
	}

	if len(t.CAFile) > 0 {
		b, err := t.readCAFile(t.CAFile)
		if err != nil {
			return nil, err
		}
		if !t.updateRootCA(tlsConfig, b) {
			return nil, fmt.Errorf("unable to use specified CA cert %s", t.CAFile)
		}
	}

	if len(t.ServerName) > 0 {
		tlsConfig.ServerName = t.ServerName
	}

	if len(t.CertFile) > 0 && len(t.KeyFile) == 0 {
		return nil, fmt.Errorf("client cert file %q specified without client key file", t.CertFile)
	} else if len(t.KeyFile) > 0 && len(t.CertFile) == 0 {
		return nil, fmt.Errorf("client key file %q specified without client cert file", t.KeyFile)
	} else if len(t.CertFile) > 0 && len(t.KeyFile) > 0 {
		if _, err := t.getClientCertificate(nil); err != nil {
			return nil, err
		}
		tlsConfig.GetClientCertificate = t.getClientCertificate
	}

	return tlsConfig, nil
}

// readCAFile 用于从本地读取 ca 证书
func (c *TLSConfig) readCAFile(f string) ([]byte, error) {
	data, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("unable to load specified CA cert %s: %s", f, err)
	}
	return data, nil
}

// updateRootCA 更新本地 ca 证书至 tls.Config.RootCAs 属性
func (c *TLSConfig) updateRootCA(t *tls.Config, b []byte) bool {
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(b) {
		return false
	}
	t.RootCAs = caCertPool
	return true
}

// getClientCertificate 用于读取本地客户端证书初始化为 tls.Certificate 实例
func (c *TLSConfig) getClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("unable to use specified client cert (%s) & key (%s): %s", c.CertFile, c.KeyFile, err)
	}
	return &cert, nil
}

// getTLSVersion 转译用户配置的 tls 版本，返回 0 则未成功转换
func (c *TLSConfig) getTLSVersion(v string) uint16 {
	switch strings.ToUpper(c.MinVersion) {
	case "TLSv1":
		return tls.VersionTLS10
	case "TLSv1.1":
		return tls.VersionTLS11
	case "TLSv1.2":
		return tls.VersionTLS12
	case "TLSv1.3":
		return tls.VersionTLS13
	}

	return 0
}
