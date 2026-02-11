package schema

import (
	"encoding/json"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// AuthProviders 身份提供商实体，验证用户登录时使用的第三方服务
// 对应 proto: AuthProvider (admin.common.proto)
// 表名: lion_auth_providers
type AuthProviders struct {
	ent.Schema
}

// Fields of the table.
func (AuthProviders) Fields() []ent.Field {
	return []ent.Field{
		// === 公共字段（独立列，支持查询和索引）===

		field.String("code").
			Unique().
			MaxLen(32).
			Comment("系统标识符，创建后不可修改"),
		field.Int("provider_type").
			Comment("提供商类型: 0=未指定, 1=LOCAL, 2=LDAP, 3=OIDC, 4=OAUTH2, 5=GITHUB, 6=GOOGLE, 7=WECHAT"),
		field.Int("provider_status").
			Default(1).
			Comment("提供商状态: 0=未指定, 1=启用, 2=禁用, 3=待配置"),
		field.String("display_name").
			Default("").
			MaxLen(256).
			Comment("展示名称，用于登录界面等用户可见场景"),
		field.String("description").
			Default("").
			Comment("提供商描述信息"),
		field.Int("sort_order").
			Default(100).
			Comment("排序权重，数值越小排序越靠前，默认 100，范围 1-9999"),
		field.String("icon_url").
			Default("").
			Comment("提供商图标地址"),

		// === 类型特有配置（JSON 列）===
		// LDAP 类型存储 LdapConfig JSON，OAuth2 系类型存储 OAuthConfig JSON
		// 不含敏感字段，敏感字段单独存储在 secret_encrypted 中
		field.JSON("config", json.RawMessage{}).
			Optional().
			Comment("类型特有的非敏感配置，JSON 格式，根据 provider_type 解析为对应结构"),

		// === 敏感字段（独立加密存储）===
		// LDAP 类型存储 bind_password
		// OAuth2 系类型存储 client_secret / app_secret
		field.Bytes("secret_encrypted").
			Sensitive().
			Optional().
			Comment("加密存储的敏感凭证：LDAP 为 bind_password，OAuth2 系为 client_secret"),
	}
}

// Edges of the table.
func (AuthProviders) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("lion_user_identities", UserIdentities.Type),
	}
}

// Mixin of the table.
func (AuthProviders) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},  // created_at, updated_at, deleted_at（支持软删除）
		AuditMixin{}, // created_by, updated_by
	}
}

// Indexes 定义索引
func (AuthProviders) Indexes() []ent.Index {
	return []ent.Index{
		// 按类型过滤查询
		index.Fields("provider_type"),
		// 按状态过滤（登录页面常用：只查启用的）
		index.Fields("provider_status"),
		// 排序展示（登录页面按 sort_order 排序）
		index.Fields("sort_order"),
	}
}

// Annotations 自定义表名
func (AuthProviders) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_auth_providers"},
	}
}
