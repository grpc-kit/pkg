package schema

import (
	"regexp"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Users 用户实体表 | 存储用户基本信息和认证相关字段
type Users struct {
	ent.Schema
}

// Fields of the table.
func (Users) Fields() []ent.Field {
	return []ent.Field{
		field.String("preferred_username").
			NotEmpty().
			Unique().
			MaxLen(255).
			Match(regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)).
			Comment("首选用户名，用于系统识别与登录，仅支持字母、数字、下划线、点号"),
		field.Bytes("realname_encrypted").
			Sensitive().
			Default([]byte("")).
			Comment("用户的真实姓名"),
		field.Bytes("idcard_encrypted").
			Sensitive().
			Default([]byte("")).
			Comment("用户身份证号码"),
		field.String("idcard_hash").
			Optional().
			Nillable().
			Comment("用户的身份证号码哈希，用于唯一值判断"),
		field.String("nickname").
			Default("").
			Comment("用户的昵称，用于页面展示"),
		field.String("profile").
			Optional().
			Nillable().
			Comment("用户个人资料页面的 URL"),
		field.String("picture").
			Optional().
			Nillable().
			Comment("用户头像的 URL"),
		field.String("website").
			Optional().
			Nillable().
			Comment("用户的个人网站 URL"),
		field.Bytes("email_encrypted").
			Sensitive().
			Default([]byte("")).
			Comment("用户的邮箱地址"),
		field.String("email_hash").
			Optional().
			Nillable().
			Comment("用户的邮箱地址哈希，用于唯一值判断"),
		field.Bool("email_verified").
			Default(false).
			Comment("邮箱是否验证过"),
		field.Enum("gender").
			Values("male", "female", "other", "unknown").
			Default("unknown").
			Comment("用户的性别，如：male、female, other"),
		field.Time("birthdate").
			Optional().
			Nillable().
			Comment("用户的出生日期，格式为 YYYY-MM-DD，如 1990-12-31"),
		field.String("zoneinfo").
			Optional().
			Nillable().
			Comment("用户的时区信息，如：Asia/Shanghai"),
		field.String("locale").
			Optional().
			Nillable().
			Comment("用户的语言/地区偏好，如：zh-CN"),
		field.Bytes("phone_number_encrypted").
			Sensitive().
			Default([]byte("")).
			Comment("用户的手机号码，加密存储"),
		field.String("phone_number_hash").
			Optional().
			Nillable().
			Comment("用户的手机号哈希，用于唯一值判断"),
		field.Bool("phone_number_verified").
			Default(false).
			Comment("手机号是否验证过"),
		field.Bytes("address_encrypted").
			Sensitive().
			Default([]byte("")).
			Comment("用户的地址信息"),
	}
}

// Edges of the table.
func (Users) Edges() []ent.Edge {
	return []ent.Edge{
		// 一个 Role 可以对应多个 RoleMenu (中间实体)
		edge.To("lion_users", RoleUserMapping.Type),
	}
}

// Mixin of the table.
func (Users) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Annotations 自定义表名
func (Users) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_users"},
	}
}
