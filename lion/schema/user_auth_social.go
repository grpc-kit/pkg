package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// UserAuthSocial 存储通过 OIDC 等社交登录的用户信息
type UserAuthSocial struct {
	ent.Schema
}

// Fields of the table.
func (UserAuthSocial) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id").
			Positive().
			Immutable().
			Comment("用户ID，关联 lion_users 表"),
		field.String("provider").
			NotEmpty().
			Comment("认证提供分，来自 lion_oauth_providers 表 name 属性"),
		field.String("provider_user_id").
			NotEmpty().
			Comment("第三方平台用户唯一标识，如微信的 OpenID"),
		field.String("provider_union_id").
			Optional().
			Comment("第三方平台统一标识，如微信的 UnionID"),
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
func (UserAuthSocial) Edges() []ent.Edge {
	/*
		return []ent.Edge{
			edge.To("user", Users{}.Type).Unique().Required().Field("user_id"),
		}
	*/
	return nil
}

// Mixin of the table.
func (UserAuthSocial) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}

// Indexes of the table.
func (UserAuthSocial) Indexes() []ent.Index {
	return []ent.Index{
		// 保证在相同平台下 provider 与 user_id 的组合唯一
		index.Fields("user_id", "provider").Unique(),
	}
}

// Annotations 自定义表名
func (UserAuthSocial) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_user_auth_social"},
	}
}
