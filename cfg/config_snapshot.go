package cfg

import (
	"encoding/json"
	"strings"
	"time"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"google.golang.org/protobuf/types/known/structpb"
)

const maskedValue = "******"

func ptrBool(v *bool, def bool) bool {
	if v == nil {
		return def
	}
	return *v
}

func ptrFloat64(v *float64, def float64) float64 {
	if v == nil {
		return def
	}
	return *v
}

func mask(v string) string {
	if v == "" {
		return ""
	}
	return maskedValue
}

func dur(v time.Duration) string {
	if v == 0 {
		return ""
	}
	return v.String()
}

func toStruct(v interface{}) *structpb.Struct {
	if v == nil {
		return nil
	}

	var m map[string]interface{}
	if mv, ok := v.(map[string]interface{}); ok {
		m = mv
	} else {
		raw, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil
		}
	}

	s, err := structpb.NewStruct(m)
	if err != nil {
		return nil
	}
	return s
}

func maskHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "auth") ||
			strings.Contains(lk, "token") ||
			strings.Contains(lk, "secret") ||
			strings.Contains(lk, "key") ||
			strings.Contains(lk, "password") {
			out[k] = mask(v)
			continue
		}
		out[k] = v
	}
	return out
}

func (c *LocalConfig) toAdminLocalConfigSnapshot() *adminv1.LocalConfig {
	if c == nil {
		return &adminv1.LocalConfig{}
	}

	return &adminv1.LocalConfig{
		Services:    c.toAdminServicesConfig(),
		Discover:    c.toAdminDiscoverConfig(),
		Security:    c.toAdminSecurityConfig(),
		Database:    c.toAdminDatabaseConfig(),
		Cachebox:    c.toAdminCacheboxConfig(),
		Debugger:    c.toAdminDebuggerConfig(),
		Objstore:    c.toAdminObjstoreConfig(),
		Frontend:    c.toAdminFrontendConfig(),
		Observables: c.toAdminObservablesConfig(),
		Cloudevents: c.toAdminCloudEventsConfig(),
		Automations: c.toAdminAutomationsConfig(),
		Independent: toStruct(c.Independent),
	}
}

func (c *LocalConfig) toAdminServicesConfig() *adminv1.ServicesConfig {
	out := &adminv1.ServicesConfig{Name: "services"}
	if c.Services == nil {
		return out
	}

	out.Enabled = true
	out.RootPath = c.Services.RootPath
	out.Namespace = c.Services.Namespace
	out.ServiceCode = c.Services.ServiceCode
	out.ApiEndpoint = c.Services.APIEndpoint
	out.GrpcAddress = c.Services.GRPCAddress
	out.HttpAddress = c.Services.HTTPAddress
	out.PublicAddress = c.Services.PublicAddress
	out.SecurityKey = mask(c.Services.SecurityKey)

	if c.Services.GRPCService != nil {
		out.GrpcService = &adminv1.GRPCServiceConfig{
			Enabled:   ptrBool(c.Services.GRPCService.Enabled, true),
			Address:   c.Services.GRPCService.Address,
			TlsServer: toAdminTLSConfig(c.Services.GRPCService.TLSServer),
		}
	}

	if c.Services.HTTPService != nil {
		out.HttpService = &adminv1.HTTPServiceConfig{
			Enabled:   ptrBool(c.Services.HTTPService.Enabled, true),
			Address:   c.Services.HTTPService.Address,
			TlsServer: toAdminTLSConfig(c.Services.HTTPService.TLSServer),
			TlsClient: toAdminTLSConfig(c.Services.HTTPService.TLSClient),
		}
		if c.Services.HTTPService.TLSAuto != nil {
			out.HttpService.TlsAuto = &adminv1.TLSAutoConfig{}
			if c.Services.HTTPService.TLSAuto.ACME != nil {
				out.HttpService.TlsAuto.Acme = &adminv1.ACMEConfig{
					Server:   c.Services.HTTPService.TLSAuto.ACME.Server,
					Email:    c.Services.HTTPService.TLSAuto.ACME.Email,
					Domains:  c.Services.HTTPService.TLSAuto.ACME.Domains,
					CacheDir: c.Services.HTTPService.TLSAuto.ACME.CacheDir,
				}
			}
			if c.Services.HTTPService.TLSAuto.SPIFFE != nil {
				out.HttpService.TlsAuto.Spiffe = &adminv1.SPIFFEConfig{
					Agent: c.Services.HTTPService.TLSAuto.SPIFFE.Agent,
				}
			}
		}
	}

	out.Integrations = &adminv1.ServicesIntegrationConfig{
		Grpc: &adminv1.ServicesIntegrationGRPCConfig{
			Admin: ptrBool(c.Services.Integrations.GRPC.Admin, false),
		},
	}

	return out
}

func (c *LocalConfig) toAdminDiscoverConfig() *adminv1.DiscoverConfig {
	out := &adminv1.DiscoverConfig{Name: "discover"}
	if c.Discover == nil {
		return out
	}
	out.Enabled = true
	out.Driver = c.Discover.Driver
	out.Endpoints = c.Discover.Endpoints
	out.Tls = toAdminTLSConfig(c.Discover.TLS)
	out.Heartbeat = c.Discover.Heartbeat
	return out
}

func (c *LocalConfig) toAdminSecurityConfig() *adminv1.SecurityConfig {
	out := &adminv1.SecurityConfig{
		Name:    "security",
		Enabled: false,
	}
	if c.Security == nil {
		return out
	}

	out.Enabled = c.Security.Enable
	if c.Security.Authentication != nil {
		out.Authentication = &adminv1.Authentication{
			InsecureRpcs: c.Security.Authentication.InsecureRPCs,
		}
		if c.Security.Authentication.OIDCProvider != nil {
			out.Authentication.OidcProvider = &adminv1.OIDCProvider{
				Issuer: c.Security.Authentication.OIDCProvider.Issuer,
			}
			if c.Security.Authentication.OIDCProvider.Config != nil {
				out.Authentication.OidcProvider.Config = &adminv1.OIDCConfig{
					ClientId:             c.Security.Authentication.OIDCProvider.Config.ClientID,
					ClientSecret:         mask(c.Security.Authentication.OIDCProvider.Config.ClientSecret),
					SupportedSigningAlgs: c.Security.Authentication.OIDCProvider.Config.SupportedSigningAlgs,
					SkipClientIdCheck:    c.Security.Authentication.OIDCProvider.Config.SkipClientIDCheck,
					SkipExpiryCheck:      c.Security.Authentication.OIDCProvider.Config.SkipExpiryCheck,
					SkipIssuerCheck:      c.Security.Authentication.OIDCProvider.Config.SkipIssuerCheck,
					InsecureSkipVerify:   c.Security.Authentication.OIDCProvider.Config.InsecureSkipVerify,
				}
			}
		}

		for _, user := range c.Security.Authentication.HTTPUsers {
			if user == nil {
				continue
			}
			out.Authentication.HttpUsers = append(out.Authentication.HttpUsers, &adminv1.BasicAuth{
				UserId:       user.UserID,
				Username:     user.Username,
				Password:     mask(user.Password),
				PasswordHash: mask(user.PasswordHash),
				Groups:       user.Groups,
				Tenant:       user.Tenant,
			})
		}
	}

	if c.Security.Authorization != nil {
		out.Authorization = &adminv1.Authorization{
			AllowedGroups: c.Security.Authorization.AllowedGroups,
			OpaNative: &adminv1.OPANativeConfig{
				Enabled: ptrBool(c.Security.Authorization.OPANative.Enabled, false),
				Policy: &adminv1.OPAPolicyConfig{
					AuthFile: c.Security.Authorization.OPANative.Policy.AuthFile,
					DataFile: c.Security.Authorization.OPANative.Policy.DataFile,
				},
			},
			OpaExternal: &adminv1.OPAExternalConfig{
				Enabled: ptrBool(c.Security.Authorization.OPAExternal.Enabled, false),
				Config:  c.Security.Authorization.OPAExternal.Config,
			},
			OpaEnvoyPlugin: &adminv1.OPAEnvoyPluginConfig{
				Enabled: ptrBool(c.Security.Authorization.OPAEnvoyPlugin.Enabled, false),
				Service: &adminv1.OPAEnvoyPluginServiceConfig{
					GrpcAddress: c.Security.Authorization.OPAEnvoyPlugin.Service.GRPCAddress,
				},
			},
		}
	}

	return out
}

func (c *LocalConfig) toAdminDatabaseConfig() *adminv1.DatabaseConfig {
	out := &adminv1.DatabaseConfig{Name: "database"}
	if c.Database == nil {
		return out
	}
	out.Enabled = c.Database.Enable
	out.Driver = c.Database.Driver
	out.Username = c.Database.Username
	out.Password = mask(c.Database.Password)
	out.Protocol = c.Database.Protocol
	out.Address = c.Database.Address
	out.Dbname = c.Database.DBName
	out.Parameters = c.Database.Parameters
	out.ConnectionPool = &adminv1.ConnectionPoolConfig{
		MaxIdleTime:  dur(c.Database.ConnectionPool.MaxIdleTime),
		MaxLifeTime:  dur(c.Database.ConnectionPool.MaxLifeTime),
		MaxIdleConns: int32(c.Database.ConnectionPool.MaxIdleConns),
		MaxOpenConns: int32(c.Database.ConnectionPool.MaxOpenConns),
	}
	return out
}

func (c *LocalConfig) toAdminCacheboxConfig() *adminv1.CacheboxConfig {
	out := &adminv1.CacheboxConfig{Name: "cachebox"}
	if c.Cachebox == nil {
		return out
	}
	out.Enabled = c.Cachebox.Enable
	out.Driver = c.Cachebox.Driver
	out.Memory = &adminv1.MemoryCacheboxConfig{MaxEntry: int32(c.Cachebox.Memory.MaxEntry)}
	out.Redis = &adminv1.RedisCacheboxConfig{
		Endpoints: c.Cachebox.Redis.Endpoints,
		Username:  c.Cachebox.Redis.Username,
		Password:  mask(c.Cachebox.Redis.Password),
		DbNumber:  int32(c.Cachebox.Redis.DBNumber),
		Sentinel: &adminv1.RedisSentinelConfig{
			MasterName: c.Cachebox.Redis.Sentinel.MasterName,
			Username:   c.Cachebox.Redis.Sentinel.Username,
			Password:   mask(c.Cachebox.Redis.Sentinel.Password),
		},
		TlsClientConfig: toAdminTLSConfig(c.Cachebox.Redis.TLSClientConfig),
	}
	return out
}

func (c *LocalConfig) toAdminDebuggerConfig() *adminv1.DebuggerConfig {
	out := &adminv1.DebuggerConfig{Name: "debugger"}
	if c.Debugger == nil {
		return out
	}
	out.Enabled = true
	out.EnablePprof = c.Debugger.EnablePprof
	out.LogLevel = c.Debugger.LogLevel
	out.LogFormat = c.Debugger.LogFormat
	return out
}

func (c *LocalConfig) toAdminObjstoreConfig() *adminv1.ObjstoreConfig {
	out := &adminv1.ObjstoreConfig{Name: "objstore"}
	if c.Objstore == nil {
		return out
	}
	out.Enabled = c.Objstore.Enable
	out.Type = c.Objstore.Type
	out.Config = &adminv1.S3Config{
		Bucket:             c.Objstore.Config.Bucket,
		Endpoint:           c.Objstore.Config.Endpoint,
		Region:             c.Objstore.Config.Region,
		AccessKey:          mask(c.Objstore.Config.AccessKey),
		Insecure:           c.Objstore.Config.Insecure,
		SecretKey:          mask(c.Objstore.Config.SecretKey),
		SessionToken:       mask(c.Objstore.Config.SessionToken),
		PutUserMetadata:    c.Objstore.Config.PutUserMetadata,
		PutUserTags:        c.Objstore.Config.PutUserTags,
		HttpConfig:         toAdminHTTPConfig(c.Objstore.Config.HTTPConfig),
		SignatureVersion:   c.Objstore.Config.SignatureVersion,
		ListObjectsVersion: c.Objstore.Config.ListObjectsVersion,
		BucketLookupType:   c.Objstore.Config.BucketLookupType,
		PartSize:           c.Objstore.Config.PartSize,
		SseConfig: &adminv1.SSEConfig{
			Type:                 c.Objstore.Config.SSEConfig.Type,
			KmsKeyId:             c.Objstore.Config.SSEConfig.KMSKeyID,
			KmsEncryptionContext: c.Objstore.Config.SSEConfig.KMSEncryptionContext,
			EncryptionKey:        mask(c.Objstore.Config.SSEConfig.EncryptionKey),
		},
	}
	return out
}

func (c *LocalConfig) toAdminFrontendConfig() *adminv1.FrontendConfig {
	out := &adminv1.FrontendConfig{Name: "frontend"}
	if c.Frontend == nil {
		return out
	}
	out.Enabled = ptrBool(c.Frontend.Enable, false)
	out.Interface = &adminv1.FrontendInterfaceConfig{
		Admin:   toAdminWebInterfaceConfig(c.Frontend.Interface.Admin),
		Openapi: toAdminWebInterfaceConfig(c.Frontend.Interface.Openapi),
		Webroot: toAdminWebInterfaceConfig(c.Frontend.Interface.Webroot),
	}
	return out
}

func (c *LocalConfig) toAdminObservablesConfig() *adminv1.ObservablesConfig {
	out := &adminv1.ObservablesConfig{Name: "observables"}
	if c.Observables == nil {
		return out
	}

	out.Enabled = ptrBool(c.Observables.Enable, true)
	if c.Observables.Telemetry != nil {
		out.Telemetry = &adminv1.TelemetryConfig{}
		if c.Observables.Telemetry.Metrics != nil {
			out.Telemetry.Metrics = &adminv1.TelemetryMetricConfig{
				Namespace:    c.Observables.Telemetry.Metrics.Namespace,
				PushInterval: int32(c.Observables.Telemetry.Metrics.PushInterval),
				ExporterEnable: &adminv1.ExporterEnableConfig{
					Otlp:       ptrBool(c.Observables.Telemetry.Metrics.Exporters.OTLP, false),
					Otlphttp:   ptrBool(c.Observables.Telemetry.Metrics.Exporters.OTLPHTTP, false),
					Logging:    ptrBool(c.Observables.Telemetry.Metrics.Exporters.Logging, false),
					Prometheus: ptrBool(c.Observables.Telemetry.Metrics.Exporters.Prometheus, false),
				},
			}
		}
		if c.Observables.Telemetry.Traces != nil {
			traceCfg := &adminv1.TelemetryTraceConfig{
				SampleRatio: ptrFloat64(c.Observables.Telemetry.Traces.SampleRatio, 1),
				ExporterEnable: &adminv1.ExporterEnableConfig{
					Otlp:       ptrBool(c.Observables.Telemetry.Traces.Exporters.OTLP, false),
					Otlphttp:   ptrBool(c.Observables.Telemetry.Traces.Exporters.OTLPHTTP, false),
					Logging:    ptrBool(c.Observables.Telemetry.Traces.Exporters.Logging, false),
					Prometheus: ptrBool(c.Observables.Telemetry.Traces.Exporters.Prometheus, false),
				},
				LogFields: &adminv1.TelemetryTraceLogFieldsConfig{
					HttpRequest:  c.Observables.Telemetry.Traces.LogFields.HTTPRequest,
					HttpResponse: c.Observables.Telemetry.Traces.LogFields.HTTPResponse,
				},
			}
			for _, f := range c.Observables.Telemetry.Traces.Filters {
				traceCfg.Filters = append(traceCfg.Filters, &adminv1.TelemetryTraceFilterConfig{
					Method:  f.Method,
					UrlPath: f.URLPath,
				})
			}
			out.Telemetry.Traces = traceCfg
		}
	}

	if c.Observables.Exporters != nil {
		out.Exporters = &adminv1.ExportersConfig{
			Otlp:     toAdminOTLPGRPCConfig(c.Observables.Exporters.OTLPGRPC),
			Otlphttp: toAdminOTLPHTTPConfig(c.Observables.Exporters.OTLPHTTP),
		}
		if c.Observables.Exporters.Prometheus != nil {
			out.Exporters.Prometheus = &adminv1.PrometheusExporterConfig{
				MetricsUrlPath: c.Observables.Exporters.Prometheus.MetricsURLPath,
			}
		}
		if c.Observables.Exporters.Logging != nil {
			out.Exporters.Logging = &adminv1.LoggingExporterConfig{
				PrettyPrint:     c.Observables.Exporters.Logging.PrettyPrint,
				MetricsFilePath: c.Observables.Exporters.Logging.MetricsFilePath,
				TracesFilePath:  c.Observables.Exporters.Logging.TracesFilePath,
			}
		}
	}

	return out
}

func (c *LocalConfig) toAdminCloudEventsConfig() *adminv1.CloudEventsConfig {
	out := &adminv1.CloudEventsConfig{Name: "cloudevents"}
	if c.CloudEvents == nil {
		return out
	}

	out.Enabled = c.CloudEvents.Enable
	out.Protocol = c.CloudEvents.Protocol
	out.KafkaSarama = &adminv1.KafkaSaramaConfig{
		Brokers: c.CloudEvents.KafkaSarama.Brokers,
		Topic:   c.CloudEvents.KafkaSarama.Topic,
		Config:  toAdminSaramaConfig(c.CloudEvents.KafkaSarama.Config),
	}
	out.AuditPolicy = &adminv1.AuditPolicyConfig{
		Enabled: c.CloudEvents.AuditPolicy.Enabled,
		Topic:   c.CloudEvents.AuditPolicy.Topic,
		Level:   c.CloudEvents.AuditPolicy.Level,
		Event: &adminv1.AuditPolicyEventConfig{
			MustSucceed: ptrBool(c.CloudEvents.AuditPolicy.Event.MustSucceed, true),
		},
	}
	return out
}

func (c *LocalConfig) toAdminAutomationsConfig() *adminv1.AutomationsConfig {
	out := &adminv1.AutomationsConfig{Name: "automations"}
	if c.Automations == nil {
		return out
	}
	out.Enabled = c.Automations.Enable
	out.Kubernetes = &adminv1.KubernetesConfig{
		ConfigPath: c.Automations.Kubernetes.ConfigPath,
	}
	if c.Automations.Kubernetes.RestConfig != nil {
		out.Kubernetes.RestConfig = &adminv1.KubernetesRestConfig{
			Host:            c.Automations.Kubernetes.RestConfig.Host,
			BearerToken:     mask(c.Automations.Kubernetes.RestConfig.BearerToken),
			BearerTokenFile: c.Automations.Kubernetes.RestConfig.BearerTokenFile,
			TlsClientConfig: &adminv1.KubernetesTLSClientConfig{
				Insecure: c.Automations.Kubernetes.RestConfig.TLSClientConfig.Insecure,
			},
		}
	}
	return out
}

func toAdminTLSConfig(c *TLSConfig) *adminv1.TLSConfig {
	if c == nil {
		return nil
	}
	return &adminv1.TLSConfig{
		ServerName:         c.ServerName,
		InsecureSkipVerify: c.InsecureSkipVerify,
		MinVersion:         c.MinVersion,
		MaxVersion:         c.MaxVersion,
		CaFile:             c.CAFile,
		CertFile:           c.CertFile,
		KeyFile:            c.KeyFile,
	}
}

func toAdminWebInterfaceConfig(c *WebInterfaceConfig) *adminv1.WebInterfaceConfig {
	if c == nil {
		return nil
	}
	return &adminv1.WebInterfaceConfig{
		Enabled:   ptrBool(c.Enabled, false),
		Embedded:  ptrBool(c.Embedded, true),
		HandleUrl: c.HandleURL,
		Tracing:   c.Tracing,
	}
}

func toAdminOTLPGRPCConfig(c *OTLPGRPCConfig) *adminv1.OTLPGRPCConfig {
	if c == nil {
		return nil
	}
	return &adminv1.OTLPGRPCConfig{
		Endpoint: c.Endpoint,
		Headers:  maskHeaders(c.Headers),
	}
}

func toAdminOTLPHTTPConfig(c *OTLPHTTPConfig) *adminv1.OTLPHTTPConfig {
	if c == nil {
		return nil
	}
	return &adminv1.OTLPHTTPConfig{
		Endpoint:       c.Endpoint,
		Headers:        maskHeaders(c.Headers),
		TracesUrlPath:  c.TracesURLPath,
		MetricsUrlPath: c.MetricsURLPath,
		LogsUrlPath:    c.LogsURLPath,
	}
}

func toAdminHTTPConfig(c HTTPConfig) *adminv1.HTTPConfig {
	return &adminv1.HTTPConfig{
		TlsClientConfig:        toAdminTLSConfig(&c.TLSClientConfig),
		TlsHandshakeTimeout:    dur(c.TLSHandshakeTimeout),
		DisableKeepAlives:      c.DisableKeepAlives,
		DisableCompression:     c.DisableCompression,
		MaxIdleConns:           int32(c.MaxIdleConns),
		MaxIdleConnsPerHost:    int32(c.MaxIdleConnsPerHost),
		MaxConnsPerHost:        int32(c.MaxConnsPerHost),
		IdleConnTimeout:        dur(c.IdleConnTimeout),
		ResponseHeaderTimeout:  dur(c.ResponseHeaderTimeout),
		ExpectContinueTimeout:  dur(c.ExpectContinueTimeout),
		MaxResponseHeaderBytes: c.MaxResponseHeaderBytes,
		WriteBufferSize:        int32(c.WriteBufferSize),
		ReadBufferSize:         int32(c.ReadBufferSize),
		ForceAttemptHttp2:      c.ForceAttemptHTTP2,
	}
}

func toAdminSaramaConfig(c SaramaConfig) *adminv1.SaramaConfig {
	return &adminv1.SaramaConfig{
		Net: &adminv1.SaramaNetConfig{
			MaxOpenRequests: int32(c.Net.MaxOpenRequests),
			DialTimeout:     dur(c.Net.DialTimeout),
			ReadTimeout:     dur(c.Net.ReadTimeout),
			WriteTimeout:    dur(c.Net.WriteTimeout),
			Tls: &adminv1.SaramaNetTLSConfig{
				Enable: c.Net.TLS.Enable,
			},
			Sasl: &adminv1.SaramaNetSASLConfig{
				Enable:    c.Net.SASL.Enable,
				Mechanism: c.Net.SASL.Mechanism,
				User:      c.Net.SASL.User,
				Password:  mask(c.Net.SASL.Password),
			},
			KeepAlive: dur(c.Net.KeepAlive),
		},
		Metadata: &adminv1.SaramaMetadataConfig{
			Retry: &adminv1.SaramaMetadataRetryConfig{
				Max:     int32(c.Metadata.Retry.Max),
				Backoff: dur(c.Metadata.Retry.Backoff),
			},
			RefreshFrequency:       dur(c.Metadata.RefreshFrequency),
			Full:                   c.Metadata.Full,
			Timeout:                dur(c.Metadata.Timeout),
			AllowAutoTopicCreation: c.Metadata.AllowAutoTopicCreation,
		},
		Producer: &adminv1.SaramaProducerConfig{
			MaxMessageBytes:  int32(c.Producer.MaxMessageBytes),
			RequiredAcks:     int32(c.Producer.RequiredAcks),
			Timeout:          dur(c.Producer.Timeout),
			Compression:      int32(c.Producer.Compression),
			CompressionLevel: int32(c.Producer.CompressionLevel),
			Idempotent:       c.Producer.Idempotent,
			Return: &adminv1.SaramaProducerReturnConfig{
				Successes: c.Producer.Return.Successes,
				Errors:    c.Producer.Return.Errors,
			},
			Flush: &adminv1.SaramaProducerFlushConfig{
				Bytes:       int32(c.Producer.Flush.Bytes),
				Messages:    int32(c.Producer.Flush.Messages),
				Frequency:   dur(c.Producer.Flush.Frequency),
				MaxMessages: int32(c.Producer.Flush.MaxMessages),
			},
			Retry: &adminv1.SaramaProducerRetryConfig{
				Max:     int32(c.Producer.Retry.Max),
				Backoff: dur(c.Producer.Retry.Backoff),
			},
		},
		Consumer: &adminv1.SaramaConsumerConfig{
			Group: &adminv1.SaramaConsumerGroupConfig{
				Session: &adminv1.SaramaConsumerGroupSessionConfig{
					Timeout: dur(c.Consumer.Group.Session.Timeout),
				},
				Heartbeat: &adminv1.SaramaConsumerGroupHeartbeatConfig{
					Interval: dur(c.Consumer.Group.Heartbeat.Interval),
				},
				Rebalance: &adminv1.SaramaConsumerGroupRebalanceConfig{
					Strategy: c.Consumer.Group.Rebalance.Strategy,
					Timeout:  dur(c.Consumer.Group.Rebalance.Timeout),
					Retry: &adminv1.SaramaConsumerGroupRebalanceRetryConfig{
						Max:     int32(c.Consumer.Group.Rebalance.Retry.Max),
						Backoff: dur(c.Consumer.Group.Rebalance.Retry.Backoff),
					},
				},
			},
			Retry: &adminv1.SaramaConsumerRetryConfig{
				Backoff: dur(c.Consumer.Retry.Backoff),
			},
			Fetch: &adminv1.SaramaConsumerFetchConfig{
				Min:         c.Consumer.Fetch.Min,
				DefaultSize: c.Consumer.Fetch.Default,
				Max:         c.Consumer.Fetch.Max,
			},
			MaxWaitTime:       dur(c.Consumer.MaxWaitTime),
			MaxProcessingTime: dur(c.Consumer.MaxProcessingTime),
			Return: &adminv1.SaramaConsumerReturnConfig{
				Errors: c.Consumer.Return.Errors,
			},
			Offsets: &adminv1.SaramaConsumerOffsetsConfig{
				AutoCommit: &adminv1.SaramaConsumerOffsetsAutoCommitConfig{
					Enable:   c.Consumer.Offsets.AutoCommit.Enable,
					Interval: dur(c.Consumer.Offsets.AutoCommit.Interval),
				},
				Initial:   c.Consumer.Offsets.Initial,
				Retention: dur(c.Consumer.Offsets.Retention),
				Retry: &adminv1.SaramaConsumerOffsetsRetryConfig{
					Max: int32(c.Consumer.Offsets.Retry.Max),
				},
			},
			IsolationLevel: int32(c.Consumer.IsolationLevel),
		},
		ClientId:          c.ClientID,
		RackId:            c.RackID,
		ChannelBufferSize: int32(c.ChannelBufferSize),
		Version:           c.Version,
	}
}
