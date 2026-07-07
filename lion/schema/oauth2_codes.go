package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// OAuth2Codes OAuth2 授权码存储表
// 表名: lion_oauth2_codes
// 存储 Authorization Code + PKCE 流程中的授权码信息
// 安全设计：不存储授权码明文，仅存储 SHA-256 hash，DB 泄露后授权码不可直接使用
type OAuth2Codes struct {
	ent.Schema
}

// Fields of the table.
func (OAuth2Codes) Fields() []ent.Field {
	return []ent.Field{
		field.String("code_hash").
			MaxLen(64).
			Unique().
			Sensitive().
			Comment("授权码的 SHA-256 哈希值，不存储明文"),
		field.String("client_id").
			MaxLen(64).
			Comment("OAuth2 客户端 ID，关联 lion_oauth2_clients.client_id"),
		field.String("redirect_uri").
			MaxLen(512).
			Comment("回调地址（签发时精确匹配）"),
		field.Int("user_id").
			Default(0).
			Comment("用户 ID，关联 lion_users 表"),
		field.String("username").
			MaxLen(255).
			Default("").
			Comment("用户名（用于 email 实时查 DB 的查询键）"),
		field.JSON("scopes", []string{}).
			Optional().
			Comment("授权范围列表"),
		field.String("state").
			MaxLen(256).
			Default("").
			Comment("state 参数，防 CSRF"),
		field.String("nonce").
			MaxLen(256).
			Default("").
			Comment("OIDC nonce 参数，用于防重放"),
		field.String("code_challenge").
			MaxLen(128).
			Default("").
			Comment("PKCE code_challenge 值"),
		field.String("code_challenge_method").
			MaxLen(16).
			Default("").
			Comment("PKCE code_challenge_method: S256 或 plain"),
		field.Time("expires_at").
			Comment("授权码过期时间"),
		field.Time("consumed_at").
			Optional().
			Nillable().
			Comment("授权码消费时间，NULL 表示未使用；非 NULL 表示已消费（替代 used bool，可审计消费时间）"),
	}
}

// Edges of the table.
func (OAuth2Codes) Edges() []ent.Edge {
	return nil
}

// Indexes 定义索引
func (OAuth2Codes) Indexes() []ent.Index {
	return []ent.Index{
		// code_hash 唯一索引已在字段定义中设置 Unique()，无需重复定义
		// 按客户端 + 过期时间查询（用于清理过期授权码）
		index.Fields("client_id", "expires_at"),
	}
}

// Mixin of the table.
func (OAuth2Codes) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{}, // 短期数据，无需软删除
	}
}

// Annotations 自定义表名
func (OAuth2Codes) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_oauth2_codes"},
	}
}
