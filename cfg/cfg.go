package cfg

import (
	"context"
	"database/sql"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	eventclient "github.com/cloudevents/sdk-go/v2/client"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/grpc-kit/pkg/sd"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
	yaml "gopkg.in/yaml.v2"
)

const (
	// HTTPHeaderRequestID 全局请求ID
	HTTPHeaderRequestID = "X-TR-REQUEST-ID"
	// TraceContextHeaderName 链路追踪ID
	TraceContextHeaderName = "jaeger-trace-id"
	// TraceBaggageHeaderPrefix 数据传递头前缀
	TraceBaggageHeaderPrefix = "jaeger-ctx"
	// AuthenticationTypeBasic 用于http basic认证
	AuthenticationTypeBasic = "basic"
	// AuthenticationTypeBearer 用于jwt认证
	AuthenticationTypeBearer = "bearer"
	// AuthenticationTypeNone 用于指明rpc未使用任何认证
	AuthenticationTypeNone = "none"
	// UsernameAnonymous 当未使用任何认证时的用户名
	UsernameAnonymous = "anonymous"
)

// contextKey 使用自定义类型不对外，防止碰撞冲突
type contextKey int

const (
	// idTokenKey 用于存放当前jwt的解析后的数据结构
	idTokenKey contextKey = iota

	// usernameKey 用于存放当前用户名，http base对应username，jwt对应email
	usernameKey

	// authenticationTypeKey 用于存放当前认证方式
	authenticationTypeKey
)

// LocalConfig 本地配置，全局微服务配置结构
type LocalConfig struct {
	Services    *ServicesConfig    `json:",omitempty"` // 基础服务配置
	Discover    *DiscoverConfig    `json:",omitempty"` // 服务注册配置
	Security    *SecurityConfig    `json:",omitempty"` // 认证鉴权配置
	Database    *DatabaseConfig    `json:",omitempty"` // 关系数据配置
	Cachebuf    *CachebufConfig    `json:",omitempty"` // 缓存服务配置
	Debugger    *DebuggerConfig    `json:",omitempty"` // 日志调试配置
	Opentracing *OpentracingConfig `json:",omitempty"` // 链路追踪配置
	CloudEvents *CloudEventsConfig `json:",omitempty"` // 公共事件配置
	Independent interface{}        `json:",omitempty"` // 应用私有配置

	logger      *logrus.Entry
	srvdis      sd.Clienter
	eventClient eventclient.Client
}

// ServicesConfig 基础服务配置，用于设定命名空间、注册的路径、监听的地址等
type ServicesConfig struct {
	RootPath      string `mapstructure:"root_path"`
	Namespace     string `mapstructure:"namespace"`
	ServiceCode   string `mapstructure:"service_code"`
	APIEndpoint   string `mapstructure:"api_endpoint"`
	GRPCAddress   string `mapstructure:"grpc_address"`
	HTTPAddress   string `mapstructure:"http_address"`
	PublicAddress string `mapstructure:"public_address"`
}

// DiscoverConfig 服务注册，服务启动后如何汇报自身
type DiscoverConfig struct {
	Driver    string     `mapstructure:"driver"`
	Endpoints []string   `mapstructure:"endpoints"`
	TLS       *TLSConfig `mapstructure:"tls" json:",omitempty"`
	Heartbeat int64      `mapstructure:"heartbeat"`
}

// SecurityConfig 安全配置，对接认证、鉴权
type SecurityConfig struct {
	// 包含*oidc.IDTokenVerifier数据结构，不能直接使用*oidc.IDTokenVerifier
	tokenVerifier atomic.Value

	Enable         bool            `mapstructure:"enable"`
	Authentication *Authentication `mapstructure:"authentication"`
	Authorization  *Authorization  `mapstructure:"authorization"`
}

// DatabaseConfig 数据库设置，指关系数据库，数据不允许丢失，如postgres、mysql
type DatabaseConfig struct {
	db *sql.DB

	Enable         bool           `mapstructure:"enable"`
	Driver         string         `mapstructure:"driver"`
	Username       string         `mapstructure:"username"`
	Password       string         `mapstructure:"password"`
	Protocol       string         `mapstructure:"protocol"`
	Address        string         `mapstructure:"address"`
	DBName         string         `mapstructure:"dbname"`
	Parameters     string         `mapstructure:"parameters"`
	ConnectionPool ConnectionPool `mapstructure:"connection_pool"`
}

// CachebufConfig 缓存配置，区别于数据库配置，缓存的数据可以丢失
type CachebufConfig struct {
	Enable   bool   `mapstructure:"enable"`
	Driver   string `mapstructure:"driver"`
	Address  string `mapstructure:"address"`
	Password string `mapstructure:"password"`
}

// DebuggerConfig 日志配置，用于设定服务启动后日志输出级别格式等
type DebuggerConfig struct {
	EnablePprof bool   `mapstructure:"enable_pprof"`
	LogLevel    string `mapstructure:"log_level"`
	LogFormat   string `mapstructure:"log_format"`
}

// OpentracingConfig 分布式链路追踪
type OpentracingConfig struct {
	Enable    bool      `mapstructure:"enable"`
	Host      string    `mapstructure:"host"`
	Port      int       `mapstructure:"port"`
	LogFields LogFields `mapstructure:"log_fields"`
}

// CloudEventsConfig cloudevents事件配置
type CloudEventsConfig struct {
	Protocol    string      `mapstructure:"protocol"`
	KafkaSarama KafkaSarama `mapstructure:"kafka_sarama"`
}

// LogFields 开启请求追踪属性
type LogFields struct {
	HTTPBody     bool `mapstructure:"http_body"`
	HTTPResponse bool `mapstructure:"http_response"`
}

// TLSConfig 证书配置
type TLSConfig struct {
	CAFile             string `mapstructure:"ca_file"`
	CertFile           string `mapstructure:"cert_file"`
	KeyFile            string `mapstructure:"key_file"`
	InsecureSkipVerify bool   `mapstructure:"insecure_skip_verify"`
}

// Authentication 用于认证
type Authentication struct {
	InsecureRPCs []string      `mapstructure:"insecure_rpcs"`
	OIDCProvider *OIDCProvider `mapstructure:"oidc_provider"`
	HTTPUsers    []*BasicAuth  `mapstructure:"http_users"`
}

// Authorization 用于鉴权
type Authorization struct {
}

// BasicAuth 用于HTTP基本认证的用户权限定义
type BasicAuth struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

// OIDCProvider 用于OIDC认证提供方配置
type OIDCProvider struct {
	Issuer string      `mapstructure:"issuer"`
	Config *OIDCConfig `mapstructure:"config"`
}

// OIDCConfig 用于OIDC验证相关配置
type OIDCConfig struct {
	ClientID             string   `mapstructure:"client_id"`
	SupportedSigningAlgs []string `mapstructure:"supported_signing_algs"`
	SkipClientIDCheck    bool     `mapstructure:"skip_client_id_check"`
	SkipExpiryCheck      bool     `mapstructure:"skip_expiry_check"`
	SkipIssuerCheck      bool     `mapstructure:"skip_issuer_check"`
	InsecureSkipVerify   bool     `mapstructure:"insecure_skip_verify"`
}

// KafkaSarama xx
type KafkaSarama struct {
	Brokers []string     `mapstructure:"brokers"`
	Topic   string       `mapstructure:"topic"`
	Config  SaramaConfig `mapstructure:"config"`
}

// ConnectionPool 数据库连接池配置
type ConnectionPool struct {
	MaxIdleTime  time.Duration `mapstructure:"max_idle_time"`
	MaxLifeTime  time.Duration `mapstructure:"max_life_time"`
	MaxIdleConns int           `mapstructure:"max_idle_conns"`
	MaxOpenConns int           `mapstructure:"max_open_conns"`
}

// SaramaConfig xx
/*
type SaramaConfig struct {
	Version                 string `mapstructure:"version"`
	NetTLSEnable            bool   `mapstructure:"net_tls_enable"`
	NetSASLEnable           bool   `mapstructure:"net_sasl_enable"`
	NetSASLMechanism        string `mapstructure:"net_sasl_mechanism"`
	NetSASLUsername         string `mapstructure:"net_sasl_username"`
	NetSASLPassword         string `mapstructure:"net_sasl_password"`
	ProducerMaxMessageBytes int    `mapstructure:"producer_max_message_bytes"`
}
*/

// New 用于初始化获取全局配置实例
func New(v *viper.Viper) (*LocalConfig, error) {
	var lc LocalConfig

	if err := viper.Unmarshal(&lc); err != nil {
		return nil, err
	}

	// 验证几个关键属性是否在
	if lc.Services.RootPath == "" {
		return nil, fmt.Errorf("unknow root_path")
	}
	if lc.Services.Namespace == "" {
		return nil, fmt.Errorf("unknow namespace")
	}
	if lc.Services.ServiceCode == "" {
		return nil, fmt.Errorf("unknow service_code")
	}
	if lc.Services.APIEndpoint == "" {
		return nil, fmt.Errorf("unknow api_endpoint")
	}

	// 初始化默认设置
	if lc.Services.GRPCAddress == "" {
		rand.Seed(time.Now().UnixNano())
		lc.Services.GRPCAddress = fmt.Sprintf("127.0.0.1:%v", 10081+rand.Intn(6000))
	}
	if lc.Services.PublicAddress == "" {
		// 支持环境变量设置微服务地址
		if addr := os.Getenv("GRPC_KIT_PUHLIC_IP"); addr != "" {
			// 获取服务端口
			tmp := strings.Split(lc.Services.GRPCAddress, ":")
			if len(tmp) == 2 {
				lc.Services.PublicAddress = fmt.Sprintf("%v:%v", addr, tmp[1])
			} else {
				lc.Services.PublicAddress = lc.Services.GRPCAddress
			}
		} else {
			lc.Services.PublicAddress = lc.Services.GRPCAddress
		}
	}

	return &lc, nil
}

// Init 用于根据配置初始化各个实例
func (c *LocalConfig) Init() error {
	if _, err := c.InitLogger(); err != nil {
		return err
	}

	if _, err := c.InitOpenTracing(); err != nil {
		return err
	}

	if err := c.InitAuthentication(); err != nil {
		return err
	}

	if err := c.InitCloudEvents(); err != nil {
		return err
	}

	if err := c.InitDatabase(); err != nil {
		return err
	}

	return nil
}

// Register 用于登记服务信息至注册中心
func (c *LocalConfig) Register(ctx context.Context,
	gw func(context.Context, *runtime.ServeMux, string, []grpc.DialOption) (err error),
	opts ...runtime.ServeMuxOption) (*http.ServeMux, error) {

	if err := c.registerConfig(); err != nil {
		return nil, err
	}

	return c.registerGateway(ctx, gw, opts...)
}

// Deregister 用于撤销注册中心上的服务信息
func (c *LocalConfig) Deregister() error {
	// 配置文件未设置注册地址，则主动忽略
	if c.Discover == nil {
		return nil
	}

	return c.srvdis.Deregister()
}

// GetIndependent 用于获取各个微服务独立的配置
func (c *LocalConfig) GetIndependent(t interface{}) error {
	if c.Independent == nil {
		return fmt.Errorf("independent is nil")
	}

	return mapstructure.Decode(c.Independent, t)
}

// GetServiceName 用于获取微服务名称
func (c *LocalConfig) GetServiceName() string {
	return fmt.Sprintf("%v.%v", c.Services.ServiceCode, c.Services.APIEndpoint)
}

func (c *LocalConfig) registerConfig() error {
	// 配置文件未设置注册地址，则主动忽略
	if c.Discover == nil {
		return nil
	}

	sd.Home(c.Services.RootPath, c.Services.Namespace)
	connector, err := sd.NewConnector(c.logger, sd.ETCDV3, strings.Join(c.Discover.Endpoints, ","))
	if err != nil {
		return err
	}

	if c.Discover.TLS != nil {
		tls := &sd.TLSInfo{
			CAFile:   c.Discover.TLS.CAFile,
			CertFile: c.Discover.TLS.CertFile,
			KeyFile:  c.Discover.TLS.KeyFile,
		}
		connector.WithTLSInfo(tls)
	}

	ttl := c.Discover.Heartbeat
	if ttl == 0 {
		ttl = 30
	}

	rawBody, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	// TODO; 服务端口开起来后在注册

	reg, err := sd.Register(connector, c.GetServiceName(), c.Services.PublicAddress, string(rawBody), ttl)
	if err != nil {
		return fmt.Errorf("Register server err: %v%v", err, "\n")
	}

	c.srvdis = reg

	// 注册解析器
	r := sd.NewResolver(connector)
	resolver.Register(r)

	return nil
}
