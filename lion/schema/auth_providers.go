package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"entgo.io/ent/schema/mixin"
)

// AuthProviders holds the schema definition for the Demo entity.
type AuthProviders struct {
	ent.Schema
}

// Fields of the table.
func (AuthProviders) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("name").
			Values("LDAP", "OIDC", "OAUTH2", "GITHUB", "WECHAT", "GOOGLE").
			Comment("支持的认证提供方"),
		field.String("client_id").
			Default(""),
		field.String("client_secret_encrypted").
			Sensitive(),
		field.String("auth_url"),      // https://open.weixin.qq.com/connect/qrconnect
		field.String("token_url"),     // https://api.weixin.qq.com/sns/oauth2/access_token
		field.String("user_info_url"), // https://api.weixin.qq.com/sns/userinfo
		field.Strings("scopes"),       // snsapi_login
		field.String("redirect_url"),  // https://your-domain.com/admin/auth/wechat/callback
	}
}

// Edges of the table.
func (AuthProviders) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (AuthProviders) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}

// Indexes of the table.
func (AuthProviders) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("name").Unique(),
	}
}

// Annotations 自定义表名
func (AuthProviders) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_auth_providers"},
	}
}
