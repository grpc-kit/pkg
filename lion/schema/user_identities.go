package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// UserIdentities 存储通过 OIDC 等社交登录的用户信息
type UserIdentities struct {
	ent.Schema
}

// Fields of the table.
func (UserIdentities) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id").
			Positive().
			Immutable().
			Comment("用户ID，关联 lion_users 表"),
		field.String("provider_name").
			NotEmpty().
			Comment("认证提供分，来自 lion_oauth_providers 表 name 属性"),
		field.String("provider_user_id").
			NotEmpty().
			Comment("第三方平台用户唯一标识，如微信的 OpenID"),
		field.String("provider_union_id").
			Optional().
			Comment("第三方平台统一标识，如微信的 UnionID"),
		field.String("password_hash").
			Default("").
			Comment("哈希后的密码"),
		field.Bool("mfa_enabled").
			Default(false).
			Comment("是否启用 MFA"),
		field.Bytes("mfa_secret_encrypted").
			Sensitive().
			Default([]byte("")).
			Comment("加密后的 MFA 密钥"),
		field.Time("password_changed_at").
			Optional().
			Nillable().
			Comment("密码最后一次更改时间"),
		field.Time("password_expires_at").
			Optional().
			Nillable().
			Comment("密码过期时间"),
		field.Bytes("access_token_encrypted").
			Sensitive().
			Optional().
			Comment("加密后的访问令牌"),
		field.Bytes("refresh_token_encrypted").
			Sensitive().
			Optional().
			Comment("加密后的刷新令牌"),
		field.Time("token_expires_at").
			Optional().
			Comment("访问令牌的过期时间"),
	}
}

// Edges of the table.
func (UserIdentities) Edges() []ent.Edge {
	/*
		return []ent.Edge{
			edge.To("user", Users{}.Type).Unique().Required().Field("user_id"),
		}
	*/
	return nil
}

// Mixin of the table.
func (UserIdentities) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Indexes of the table.
func (UserIdentities) Indexes() []ent.Index {
	return []ent.Index{
		// 保证在相同平台下 provider 与 user_id 的组合唯一
		index.Fields("user_id", "provider_name").Unique(),
	}
}

// Annotations 自定义表名
func (UserIdentities) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_user_identities"},
	}
}
