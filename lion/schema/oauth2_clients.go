package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OAuth2Clients OAuth2 客户端注册表
// 表名: lion_oauth2_clients
// 存储 OAuth2 客户端注册信息，支持 Authorization Code + PKCE + Refresh Token 流程
type OAuth2Clients struct {
	ent.Schema
}

// Fields of the table.
func (OAuth2Clients) Fields() []ent.Field {
	return []ent.Field{
		field.String("client_id").
			MaxLen(64).
			Unique().
			Comment("OAuth2 客户端 ID，创建后不可修改，关联 lion_oauth2_clients 表唯一标识"),
		field.String("client_secret_hash").
			MaxLen(128).
			Sensitive().
			Comment("客户端密钥的 bcrypt 哈希值"),
		field.String("display_name").
			MaxLen(128).
			Default("").
			Comment("客户端显示名称"),
		field.JSON("redirect_uris", []string{}).
			Optional().
			Comment("回调地址列表（支持多个）"),
		field.Int("client_status").
			Default(1).
			Comment("状态: 1=启用, 2=禁用, 3=已吊销"),
		field.JSON("grant_types", []string{}).
			Optional().
			Comment("支持的授权类型，如 authorization_code, refresh_token"),
		field.JSON("scopes", []string{}).
			Optional().
			Comment("授权范围列表"),
		field.String("logo_url").
			MaxLen(512).
			Default("").
			Comment("客户端 Logo URL"),
		field.String("description").
			MaxLen(512).
			Default("").
			Comment("客户端描述"),
	}
}

// Edges of the table.
func (OAuth2Clients) Edges() []ent.Edge {
	return nil
}

// Indexes 定义索引
func (OAuth2Clients) Indexes() []ent.Index {
	return []ent.Index{
		// client_id 唯一索引已在字段定义中设置 Unique()，无需重复定义
		// 按状态过滤查询（管理后台常用）
		index.Fields("client_status"),
	}
}

// Mixin of the table.
func (OAuth2Clients) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},  // created_at, updated_at, deleted_at（支持软删除，与 auth_providers 对齐）
		AuditMixin{}, // created_by, updated_by
	}
}

// Annotations 自定义表名
func (OAuth2Clients) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_oauth2_clients"},
	}
}
