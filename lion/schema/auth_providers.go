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
			Values("LOCAL", "LDAP", "OIDC", "OAUTH2", "GITHUB", "WECHAT", "GOOGLE").
			Comment("支持的认证提供方"),
		field.String("client_id").
			Default(""),
		field.Bool("enabled").
			Default(false),
		field.Bytes("client_secret_encrypted").
			Sensitive().
			Default([]byte("")),
		field.String("issuer"),        // https://open.weixin.qq.com/connect/qrconnect
		field.String("auth_url"),      // https://open.weixin.qq.com/connect/qrconnect
		field.String("token_url"),     // https://api.weixin.qq.com/sns/oauth2/access_token
		field.String("user_info_url"), // https://api.weixin.qq.com/sns/userinfo
		field.String("scopes"),        // snsapi_login
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

// 考虑还是在应用层选择加密、解密
/*
func (AuthProviders) Hooks() []ent.Hook {
	return []ent.Hook{
		crypto.EncryptedMixin(),
	}
}
*/

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
