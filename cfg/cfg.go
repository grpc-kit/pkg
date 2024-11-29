package cfg

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	eventclient "github.com/cloudevents/sdk-go/v2/client"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/rpc"
	"github.com/grpc-kit/pkg/sd"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/resolver"
)

const (
	// AuthenticationTypeBasic 用于http basic认证
	AuthenticationTypeBasic = "basic"
	// AuthenticationTypeBearer 用于jwt认证
	AuthenticationTypeBearer = "bearer"
	// AuthenticationTypeNone 用于指明rpc未使用任何认证
	AuthenticationTypeNone = "none"
	// UsernameAnonymous 当未使用任何认证时的用户名
	UsernameAnonymous = "anonymous"
)

// 公共标准的 HTTP 请求头名称
const (
	// HTTPHeaderRequestID 全局请求ID
	HTTPHeaderRequestID = "X-TR-REQUEST-ID"
	// HTTPHeaderHost 主机头
	HTTPHeaderHost = "Host"
	// HTTPHeaderEtag 文件内容签名
	HTTPHeaderEtag = "Etag"
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

	// groupsKey 用于存放当前用户归属的组列表
	groupsKey
)

const (
	// ScopeNameGRPCKit 用于该包产生链路、指标的权威名称
	ScopeNameGRPCKit = "github.com/grpc-kit/pkg"
)

// LocalConfig 本地配置，全局微服务配置结构
type LocalConfig struct {
	Services    *ServicesConfig    `json:",omitempty"` // 基础服务配置
	Discover    *DiscoverConfig    `json:",omitempty"` // 服务注册配置
	Security    *SecurityConfig    `json:",omitempty"` // 认证鉴权配置
	Database    *DatabaseConfig    `json:",omitempty"` // 关系数据配置
	Cachebox    *CacheboxConfig    `json:",omitempty"` // 缓存服务配置
	Debugger    *DebuggerConfig    `json:",omitempty"` // 日志调试配置
	Objstore    *ObjstoreConfig    `json:",omitempty"` // 对象存储配置
	Frontend    *FrontendConfig    `json:",omitempty"` // 前端服务配置
	Observables *ObservablesConfig `json:",omitempty"` // 可观测性配置
	CloudEvents *CloudEventsConfig `json:",omitempty"` // 公共事件配置
	Automations *AutomationsConfig `json:",omitempty"` // 流程编排配置
	Independent interface{}        `json:",omitempty"` // 应用私有配置

	logger      *logrus.Entry
	srvdis      sd.Registry
	rpcConfig   *rpc.Config
	eventClient eventclient.Client
	// promRegistry *prometheus.Registry

	// Opentracing *OpentracingConfig `json:",omitempty"` // 链路追踪配置
}

// ServicesConfig 基础服务配置，用于设定命名空间、注册的路径、监听的地址等
type ServicesConfig struct {
	RootPath    string `mapstructure:"root_path"`
	Namespace   string `mapstructure:"namespace"`
	ServiceCode string `mapstructure:"service_code"`
	APIEndpoint string `mapstructure:"api_endpoint"`
	// Deprecated: 使用 GRPCService 代替，优先级低于 GRPCService 配置
	GRPCAddress string `mapstructure:"grpc_address"`
	// Deprecated: 使用 HTTPService 代替，优先级低于 HTTPService 配置
	HTTPAddress   string       `mapstructure:"http_address"`
	PublicAddress string       `mapstructure:"public_address"`
	GRPCService   *GRPCService `mapstructure:"grpc_service"`
	HTTPService   *HTTPService `mapstructure:"http_service"`
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
	authClient    *auth.Client

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

// DebuggerConfig 日志配置，用于设定服务启动后日志输出级别格式等
type DebuggerConfig struct {
	EnablePprof bool   `mapstructure:"enable_pprof"`
	LogLevel    string `mapstructure:"log_level"`
	LogFormat   string `mapstructure:"log_format"`
}

// CloudEventsConfig cloudevents事件配置
type CloudEventsConfig struct {
	Protocol    string      `mapstructure:"protocol"`
	KafkaSarama KafkaSarama `mapstructure:"kafka_sarama"`
}

// Authentication 用于认证
type Authentication struct {
	InsecureRPCs []string      `mapstructure:"insecure_rpcs"`
	OIDCProvider *OIDCProvider `mapstructure:"oidc_provider"`
	HTTPUsers    []*BasicAuth  `mapstructure:"http_users"`
}

// Authorization 用于鉴权
type Authorization struct {
	AllowedGroups  []string       `mapstructure:"allowed_groups"`
	OPANative      OPANative      `mapstructure:"opa_native"`
	OPAExternal    OPAExternal    `mapstructure:"opa_external"`
	OPAEnvoyPlugin OPAEnvoyPlugin `mapstructure:"opa_envoy_plugin"`
}

// BasicAuth 用于HTTP基本认证的用户权限定义
type BasicAuth struct {
	Username string   `mapstructure:"username"`
	Password string   `mapstructure:"password"`
	Groups   []string `mapstructure:"groups"`
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

	return &lc, nil
}

// Init 用于根据配置初始化各个实例，初始化需注意空指针判断
func (c *LocalConfig) Init() error {
	if err := c.initDebugger(); err != nil {
		return err
	}

	if err := c.initServices(); err != nil {
		return err
	}

	if err := c.initSecurity(); err != nil {
		return err
	}

	if err := c.initDatabase(); err != nil {
		return err
	}

	if err := c.initCachebox(); err != nil {
		return err
	}

	if err := c.initObservables(); err != nil {
		return err
	}

	if err := c.initCloudEvents(); err != nil {
		return err
	}

	if err := c.initRPCConfig(); err != nil {
		return err
	}

	if err := c.initObjstore(); err != nil {
		return err
	}

	if err := c.initFrontend(); err != nil {
		return err
	}

	if err := c.initAutomations(); err != nil {
		return err
	}

	return nil
}

// Register 用于登记服务信息至注册中心
func (c *LocalConfig) Register(ctx context.Context,
	gw func(context.Context, *runtime.ServeMux, string, []grpc.DialOption) (err error),
	opts ...runtime.ServeMuxOption) (*http.ServeMux, error) {

	if err := c.registerConfig(ctx); err != nil {
		return nil, err
	}

	return c.registerGateway(ctx, gw, opts...)
}

// Deregister 用于撤销注册中心上的服务信息
func (c *LocalConfig) Deregister() error {
	// TODO; 释放各总资源
	ctx := context.TODO()
	if err := c.Observables.shutdown(ctx); err != nil {
		return err
	}

	// 配置文件未设置注册地址，则主动忽略
	if c.Discover == nil || c.srvdis == nil {
		return nil
	}

	return c.srvdis.Deregister()
}

// GetIndependent 用于获取各个微服务独立的配置
func (c *LocalConfig) GetIndependent(t interface{}) error {
	if c.Independent == nil {
		return fmt.Errorf("independent is nil")
	}

	// return mapstructure.Decode(c.Independent, t)
	// 使用全局 Decode 仅仅支持基础类型，当配置结构体存在 time.Duration 类型则无法解析，会产生类似以下错误：
	// expected type 'time.Duration', got unconvertible type 'string', value: '10s'
	//
	// 参考 viper 通过自定义解析器解决
	// https://github.com/spf13/viper/blob/master/viper.go#L1152
	// github.com/spf13/viper/viper.go -> defaultDecoderConfig
	dc := &mapstructure.DecoderConfig{
		Metadata:         nil,
		Result:           t,
		WeaklyTypedInput: true,
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(",")),
	}

	dr, err := mapstructure.NewDecoder(dc)
	if err != nil {
		return err
	}

	return dr.Decode(c.Independent)
}

// GetServiceName 用于获取微服务名称
func (c *LocalConfig) GetServiceName() string {
	return fmt.Sprintf("%v.%v", c.Services.ServiceCode, c.Services.APIEndpoint)
}

// GetTraceID 用于获取 opentelemetry 下的 trace id
func (c *LocalConfig) GetTraceID(ctx context.Context) string {
	return c.Observables.calcRequestID(ctx)
}

// HTTPHandlerFunc 功能同 HTTPHandler
func (c *LocalConfig) HTTPHandlerFunc(handler http.HandlerFunc) http.Handler {
	return c.HTTPHandler(handler)
}

// HTTPHandler 用于植入 otelhttp 链路跟踪与鉴权中间件
func (c *LocalConfig) HTTPHandler(handler http.Handler) http.Handler {
	handler = c.Observables.addHTTPHandler(handler)
	handler = c.Security.addHTTPHandler(handler)
	return handler
}

// HTTPHandlerFrontend 用于处理前端相关服务
func (c *LocalConfig) HTTPHandlerFrontend(mux *http.ServeMux, assets fs.FS) error {
	if !*c.Frontend.Enable {
		return nil
	}

	comps := []string{"admin", "openapi", "webroot"}
	for _, v := range comps {
		tracing := false

		switch v {
		case "admin":
			tracing = c.Frontend.Interface.Admin.Tracing
		case "openapi":
			tracing = c.Frontend.Interface.Openapi.Tracing
		case "webroot":
			tracing = c.Frontend.Interface.Webroot.Tracing
		default:
			tracing = false
		}

		handle, url, ok, err := c.Frontend.getHandler(assets, v)
		if err == nil && ok {
			if tracing {
				handle = c.HTTPHandler(handle)
			} else {
				handle = c.Security.addHTTPHandler(handle)
			}

			mux.Handle(url, handle)
		} else if err != nil {
			return err
		}
	}

	return nil
}

// SecurityPolicyLoad 加载服务本地安全策略
func (c *LocalConfig) SecurityPolicyLoad(ctx context.Context, assets embed.FS) error {
	tmps := strings.Split(c.Services.ServiceCode, ".")
	if len(tmps) != 3 {
		return fmt.Errorf("invalid service code, must be like 'xxx.yyy.zzz'")
	}

	packageName := fmt.Sprintf("%v.%v.%v", tmps[2], tmps[0], tmps[1])

	// 内嵌的策略文件
	embedAuthFile, err := assets.ReadFile("auth.rego")
	if err != nil {
		return err
	}
	embedDataFile, err := assets.ReadFile("data.yaml")
	if err != nil {
		return err
	}

	localAuthFile := c.Security.Authorization.OPANative.Policy.AuthFile
	localDataFile := c.Security.Authorization.OPANative.Policy.DataFile
	if localAuthFile != "" {
		embedAuthFile, err = os.ReadFile(localAuthFile)
		if err != nil {
			return err
		}
	}
	if localDataFile != "" {
		embedDataFile, err = os.ReadFile(localDataFile)
		if err != nil {
			return err
		}
	}

	return c.Security.initAuthClient(ctx, c.logger, packageName, embedAuthFile, embedDataFile)
}

// GetFlowClientConfig 用于获取 flow client 配置
func (c *LocalConfig) GetFlowClientConfig() (*FlowClientConfig, error) {
	if !c.Automations.Enable {
		return nil, fmt.Errorf("automations is not enable")
	}

	fcc := &FlowClientConfig{
		Config:    c.Automations.restConfig,
		Namespace: c.GetNamespace(),
		Appname:   c.GetAppname(),
	}

	return fcc, nil
}

// GetNamespace 用于获取应用的命名空间
func (c *LocalConfig) GetNamespace() string {
	if c.Services.Namespace == "" {
		panic("namespace is not set")
	}

	return c.Services.Namespace
}

// GetAppname 用于获取应用名称
func (c *LocalConfig) GetAppname() string {
	// 这里的 ServiceCode 格式一定是 xxx.yyy.zzz 格式
	parts := strings.Split(c.Services.ServiceCode, ".")
	if len(parts) != 3 {
		panic("invalid service code, must be like 'xxx.yyy.zzz'")
	}

	return fmt.Sprintf("%s-%s-%s", parts[2], parts[0], parts[1])
}

// GetLRUCachebox 用于获取 LRU 缓存
func (c *LocalConfig) GetLRUCachebox() (LRUCachebox, error) {
	if c.Cachebox.Enable {
		return c.Cachebox.lruCache, nil
	}

	return nil, fmt.Errorf("cachebox is not enabled")
}

// HasCacheboxEnabled 用于判断是否启用缓存
func (c *LocalConfig) HasCacheboxEnabled() bool {
	return c.Cachebox.Enable
}

func (c *LocalConfig) registerConfig(ctx context.Context) error {
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

	rawBody, err := json.Marshal(c)
	if err != nil {
		return err
	}

	// 确保服务端口开起来后在注册
	tryConnect := func(address string) error {
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			return err
		}
		return conn.Close()
	}

	go func() {
		retryMax := 5
		retryCount := 0
		allowRegistry := true

		for retryCount < retryMax {
			retryCount += 1

			time.Sleep(3 * time.Second)

			if err := tryConnect(c.Services.PublicAddress); err != nil {
				c.logger.Errorf("register service the grpc health check err: %v, retry_count: %v, retry_max: %v",
					err, retryCount, retryMax)

				continue
			}

			c.logger.Infof("register service the grpc health check public_address: %v success",
				c.Services.PublicAddress)
			break
		}

		if retryCount >= retryMax {
			allowRegistry = false

			c.logger.Errorf("register service the grpc health check fail public_address: %v will not public to registry",
				c.Services.PublicAddress)

			// TODO; 达到最大检测次数，但后端服务端口还未正常，此时应该发送信号退出应用，不允许注册
		}

		// TODO; 如果后端grpc服务未正常注册，前端必须配合http健康检测，http状态码为503
		if allowRegistry {
			reg, err := sd.Register(connector, c.GetServiceName(), c.Services.PublicAddress, string(rawBody), ttl)
			if err != nil {
				c.logger.Errorf("register service err: %v%v", err, "\n")
			}

			c.srvdis = reg

			// TODO; 注册解析器，目前在全局，建议在dial中配置（grpc 1.27以后支持）
			resolver.Register(reg)
		}
	}()

	return nil
}
