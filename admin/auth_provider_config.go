package admin

import (
	"encoding/json"
	"fmt"
	"strings"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/lion"
)

// ldapConfigData LDAP 非敏感配置，用于 JSON 列存储
// bind_password 不在此处，单独存储在 secret_encrypted 列
type ldapConfigData struct {
	Host                 string `json:"host,omitempty"`
	Port                 int32  `json:"port,omitempty"`
	UseTLS               bool   `json:"use_tls,omitempty"`
	StartTLS             bool   `json:"start_tls,omitempty"`
	InsecureSkipVerify   bool   `json:"insecure_skip_verify,omitempty"`
	BindDN               string `json:"bind_dn,omitempty"`
	UserSearchBase       string `json:"user_search_base,omitempty"`
	UserSearchFilter     string `json:"user_search_filter,omitempty"`
	UsernameAttribute    string `json:"username_attribute,omitempty"`
	EmailAttribute       string `json:"email_attribute,omitempty"`
	DisplayNameAttribute string `json:"display_name_attribute,omitempty"`
	GroupSearchBase      string `json:"group_search_base,omitempty"`
	GroupSearchFilter    string `json:"group_search_filter,omitempty"`
}

// oauthConfigData OAuth2 系非敏感配置，用于 JSON 列存储
// client_secret 不在此处，单独存储在 secret_encrypted 列
type oauthConfigData struct {
	ClientID              string   `json:"client_id,omitempty"`
	RedirectURI           string   `json:"redirect_uri,omitempty"`
	Scopes                []string `json:"scopes,omitempty"`
	AuthorizationEndpoint string   `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string   `json:"token_endpoint,omitempty"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint,omitempty"`
	// OIDC 特有
	Issuer  string `json:"issuer,omitempty"`
	JwksURI string `json:"jwks_uri,omitempty"`
	// OAuth2 字段映射
	UserinfoIdField    string `json:"userinfo_id_field,omitempty"`
	UserinfoNameField  string `json:"userinfo_name_field,omitempty"`
	UserinfoEmailField string `json:"userinfo_email_field,omitempty"`
	// GitHub 特有
	AllowedOrganizations []string `json:"allowed_organizations,omitempty"`
	ApiURL               string   `json:"api_url,omitempty"`
	// Google 特有
	HostedDomain string `json:"hosted_domain,omitempty"`
	// WeChat 特有
	AgentID      string `json:"agent_id,omitempty"`
	IsEnterprise bool   `json:"is_enterprise,omitempty"`
	// 通用安全选项
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

// protoToDBConfig 从 proto AuthProvider 中提取配置和敏感凭证
// 返回 JSON 配置（不含敏感字段）和加密后的敏感凭证
func protoToDBConfig(p *adminv1.AuthProvider, aesKey []byte) (configJSON json.RawMessage, secretEnc []byte, err error) {
	var secret string

	switch cfg := p.GetConfig().(type) {
	case *adminv1.AuthProvider_LdapConfig:
		lc := cfg.LdapConfig
		secret = lc.GetBindPassword()
		data := &ldapConfigData{
			Host:                 lc.GetHost(),
			Port:                 lc.GetPort(),
			UseTLS:               lc.GetUseTls(),
			StartTLS:             lc.GetStartTls(),
			InsecureSkipVerify:   lc.GetInsecureSkipVerify(),
			BindDN:               lc.GetBindDn(),
			UserSearchBase:       lc.GetUserSearchBase(),
			UserSearchFilter:     lc.GetUserSearchFilter(),
			UsernameAttribute:    lc.GetUsernameAttribute(),
			EmailAttribute:       lc.GetEmailAttribute(),
			DisplayNameAttribute: lc.GetDisplayNameAttribute(),
			GroupSearchBase:      lc.GetGroupSearchBase(),
			GroupSearchFilter:    lc.GetGroupSearchFilter(),
		}
		configJSON, err = json.Marshal(data)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal ldap config: %w", err)
		}

	case *adminv1.AuthProvider_OauthConfig:
		oc := cfg.OauthConfig
		secret = oc.GetClientSecret()
		isGoogleProvider := p.GetType() == adminv1.AuthProvider_GOOGLE
		isGithubProvider := p.GetType() == adminv1.AuthProvider_GITHUB
		isWechatProvider := p.GetType() == adminv1.AuthProvider_WECHAT
		authorizationEndpoint := strings.TrimSpace(oc.GetAuthorizationEndpoint())
		if authorizationEndpoint == "" && isGithubProvider {
			authorizationEndpoint = "https://github.com/login/oauth/authorize"
		}
		if authorizationEndpoint == "" && isWechatProvider {
			authorizationEndpoint = "https://api.weixin.qq.com/sns/jscode2session"
		}
		tokenEndpoint := strings.TrimSpace(oc.GetTokenEndpoint())
		if tokenEndpoint == "" && isGithubProvider {
			tokenEndpoint = "https://github.com/login/oauth/access_token"
		}
		userinfoEndpoint := strings.TrimSpace(oc.GetUserinfoEndpoint())
		if userinfoEndpoint == "" && isGithubProvider {
			userinfoEndpoint = "https://api.github.com/user"
		}
		issuer := strings.TrimSpace(oc.GetIssuer())
		if issuer == "" && isGoogleProvider {
			issuer = "https://accounts.google.com"
		}
		data := &oauthConfigData{
			ClientID:              oc.GetClientId(),
			RedirectURI:           oc.GetRedirectUri(),
			Scopes:                oc.GetScopes(),
			AuthorizationEndpoint: authorizationEndpoint,
			TokenEndpoint:         tokenEndpoint,
			UserinfoEndpoint:      userinfoEndpoint,
			Issuer:                issuer,
			JwksURI:               oc.GetJwksUri(),
			UserinfoIdField:       oc.GetUserinfoIdField(),
			UserinfoNameField:     oc.GetUserinfoNameField(),
			UserinfoEmailField:    oc.GetUserinfoEmailField(),
			AllowedOrganizations:  oc.GetAllowedOrganizations(),
			ApiURL:                oc.GetApiUrl(),
			HostedDomain:          oc.GetHostedDomain(),
			AgentID:               oc.GetAgentId(),
			IsEnterprise:          oc.GetIsEnterprise(),
			InsecureSkipVerify:    oc.GetInsecureSkipVerify(),
		}
		configJSON, err = json.Marshal(data)
		if err != nil {
			return nil, nil, fmt.Errorf("marshal oauth config: %w", err)
		}

	default:
		// LOCAL 类型或无配置
		configJSON = nil
	}

	// 加密敏感凭证
	if secret != "" {
		secretEnc, err = crypto.EncryptAES(aesKey, []byte(secret))
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt secret: %w", err)
		}
	}

	return configJSON, secretEnc, nil
}

// dbToProtoAuthProvider 将 DB 行转换为 proto AuthProvider
// withSecret 控制是否解密并填充敏感字段（List 场景不需要，Get 场景需要）
func dbToProtoAuthProvider(row *lion.AuthProviders, aesKey []byte, withSecret bool) (*adminv1.AuthProvider, error) {
	p := &adminv1.AuthProvider{
		Id:          int64(row.ID),
		Code:        row.Code,
		Type:        adminv1.AuthProvider_Type(row.ProviderType),
		Status:      adminv1.AuthProvider_Status(row.ProviderStatus),
		DisplayName: row.DisplayName,
		Description: row.Description,
		SortOrder:   int32(row.SortOrder),
		IconUrl:     row.IconURL,
	}

	// 解密敏感凭证
	var secret string
	if withSecret && len(row.SecretEncrypted) > 0 {
		decrypted, err := crypto.DecryptAES(aesKey, row.SecretEncrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt secret: %w", err)
		}
		secret = string(decrypted)
	}

	// 根据 type 解析 config JSON 并构建 oneof config
	if len(row.Config) > 0 {
		switch p.Type {
		case adminv1.AuthProvider_LDAP:
			var data ldapConfigData
			if err := json.Unmarshal(row.Config, &data); err != nil {
				return nil, fmt.Errorf("unmarshal ldap config: %w", err)
			}
			lc := &adminv1.LdapConfig{
				Host:                 data.Host,
				Port:                 data.Port,
				UseTls:               data.UseTLS,
				StartTls:             data.StartTLS,
				InsecureSkipVerify:   data.InsecureSkipVerify,
				BindDn:               data.BindDN,
				UserSearchBase:       data.UserSearchBase,
				UserSearchFilter:     data.UserSearchFilter,
				UsernameAttribute:    data.UsernameAttribute,
				EmailAttribute:       data.EmailAttribute,
				DisplayNameAttribute: data.DisplayNameAttribute,
				GroupSearchBase:      data.GroupSearchBase,
				GroupSearchFilter:    data.GroupSearchFilter,
			}
			if withSecret {
				lc.BindPassword = secret
			}
			p.Config = &adminv1.AuthProvider_LdapConfig{LdapConfig: lc}

		case adminv1.AuthProvider_OIDC, adminv1.AuthProvider_OAUTH2,
			adminv1.AuthProvider_GITHUB, adminv1.AuthProvider_GOOGLE,
			adminv1.AuthProvider_WECHAT:
			var data oauthConfigData
			if err := json.Unmarshal(row.Config, &data); err != nil {
				return nil, fmt.Errorf("unmarshal oauth config: %w", err)
			}
			oc := &adminv1.OAuthConfig{
				ClientId:              data.ClientID,
				RedirectUri:           data.RedirectURI,
				Scopes:                data.Scopes,
				AuthorizationEndpoint: data.AuthorizationEndpoint,
				TokenEndpoint:         data.TokenEndpoint,
				UserinfoEndpoint:      data.UserinfoEndpoint,
				Issuer:                data.Issuer,
				JwksUri:               data.JwksURI,
				UserinfoIdField:       data.UserinfoIdField,
				UserinfoNameField:     data.UserinfoNameField,
				UserinfoEmailField:    data.UserinfoEmailField,
				AllowedOrganizations:  data.AllowedOrganizations,
				ApiUrl:                data.ApiURL,
				HostedDomain:          data.HostedDomain,
				AgentId:               data.AgentID,
				IsEnterprise:          data.IsEnterprise,
				InsecureSkipVerify:    data.InsecureSkipVerify,
			}
			if withSecret {
				oc.ClientSecret = secret
			}
			p.Config = &adminv1.AuthProvider_OauthConfig{OauthConfig: oc}
		}
	}

	return p, nil
}

// parseOAuthConfigFromDB 从 DB 行解析 OAuth 配置和解密后的凭证
// 供 socialUsers 内部认证流程使用
func parseOAuthConfigFromDB(row *lion.AuthProviders, aesKey []byte) (*oauthConfigData, string, error) {
	var cfg oauthConfigData
	if len(row.Config) > 0 {
		if err := json.Unmarshal(row.Config, &cfg); err != nil {
			return nil, "", fmt.Errorf("unmarshal oauth config: %w", err)
		}
	}

	var secret string
	if len(row.SecretEncrypted) > 0 {
		decrypted, err := crypto.DecryptAES(aesKey, row.SecretEncrypted)
		if err != nil {
			return nil, "", fmt.Errorf("decrypt secret: %w", err)
		}
		secret = string(decrypted)
	}

	return &cfg, secret, nil
}
