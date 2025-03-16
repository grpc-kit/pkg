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
		field.Enum("provider").
			Values("general_oidc", "weixin", "github").
			Comment("第三方认证平台"),
		field.String("provider_id").
			Comment("第三方平台用户唯一标识"),
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
		index.Fields("user_id", "provider").Unique(),
	}
}

// Annotations 自定义表名
func (UserAuthSocial) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_user_auth_social"},
	}
}
