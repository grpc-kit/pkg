package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

// OAuthProviders holds the schema definition for the Demo entity.
type OAuthProviders struct {
	ent.Schema
}

// Fields of the table.
func (OAuthProviders) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("name").
			Values("general_oidc", "wechat", "twitter").
			Comment("OAuth 认证提供分，如：wechat 等"),
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
func (OAuthProviders) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (OAuthProviders) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}

// Annotations 自定义表名
func (OAuthProviders) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_oauth_providers"},
	}
}
