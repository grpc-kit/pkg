package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// AuthProviders holds the schema definition for the Demo entity.
type AuthProviders struct {
	ent.Schema
}

// Fields of the table.
func (AuthProviders) Fields() []ent.Field {
	return []ent.Field{
		field.Enum("name").
			Values("LOCAL", "LDAP", "OIDC", "OAUTH2", "GITHUB", "GOOGLE", "WECHAT").
			Comment("支持的认证提供方"),
		field.String("client_id").
			Default(""),
		field.Bool("enabled").
			Default(false),
		field.Bytes("client_secret_encrypted").
			Sensitive().
			Default([]byte("")),
		field.String("scopes"),       // snsapi_login
		field.String("redirect_uri"), // https://your-domain.com/admin/auth/wechat/callback
		// 以下参考 openid 关键属性
		// https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
		// issuer 认证提供方的唯一标识符，不包含查询参数
		// 如：http://id.example.com/oauth2 或 https://open.weixin.qq.com/connect/qrconnect
		field.String("issuer"),
		// authorization_endpoint 认证端点
		// 如：http://id.example.com/oauth2/auth/local 或 https://open.weixin.qq.com/connect/qrconnect
		field.String("authorization_endpoint"),
		// token_endpoint 令牌端点
		// 如：http://id.example.com/oauth2/token 或 https://api.weixin.qq.com/sns/oauth2/access_token
		field.String("token_endpoint"),
		// userinfo_endpoint 用户端点
		// 如：http://account.example.com/userinfo、https://api.weixin.qq.com/sns/userinfo
		field.String("userinfo_endpoint"),
	}
}

// Edges of the table.
func (AuthProviders) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (AuthProviders) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
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
