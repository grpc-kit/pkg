package schema

/*
import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// UserAuthLocal 存储本地用户的认证信息（如密码）
type UserAuthLocal struct {
	ent.Schema
}

// Fields of the table.
func (UserAuthLocal) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id").
			Unique().
			Positive().
			Immutable().
			Comment("用户ID，关联 lion_users 表"),
		field.Bytes("password_hash").
			NotEmpty().
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
	}
}

// Edges of the table.
func (UserAuthLocal) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (UserAuthLocal) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Annotations 自定义表名
func (UserAuthLocal) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_user_auth_local"},
	}
}
*/
