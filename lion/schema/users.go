package schema

import (
	"regexp"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
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
			Match(regexp.MustCompile(`^[a-zA-Z0-9_.]+$`)).
			Comment("首选用户名，用于系统识别与登录，仅支持字母、数字、下划线、点号"),
		field.Bytes("name").
			Sensitive().
			Default([]byte("")).
			Comment("用户的真实姓名"),
		/*
			field.String("family_name").
				Default("").
				Comment("用户的姓氏"),
			field.String("given_name").
				Default("").
				Comment("用户的名字"),
		*/
		field.String("nickname").
			Default("").
			Comment("用户的昵称，用于页面展示"),
		field.String("profile").
			Default("").
			Comment("用户个人资料页面的 URL"),
		field.String("picture").
			Default("").
			Comment("用户头像的 URL"),
		field.String("website").
			Default("").
			Comment("用户的个人网站 URL"),
		field.Bytes("email_encrypted").
			Sensitive().
			Default([]byte("")).
			Comment("用户的邮箱地址"),
		field.Bool("email_verified").
			Default(false).
			Comment("邮箱是否验证过"),
		field.Enum("gender").
			Values("male", "female", "other", "unknown").
			Default("unknown").
			Comment("用户的性别，如：male、female, other"),
		field.Time("birthdate").
			Default(time.Time{}).
			Comment("用户的出生日期，格式为 YYYY-MM-DD，如 1990-12-31"),
		field.String("zoneinfo").
			Default("Asia/Shanghai").
			Comment("用户的时区信息，如：Asia/Shanghai"),
		field.String("locale").
			Default("").
			Comment("用户的语言/地区偏好，如：zh-CN"),
		field.Bytes("phone_number_encrypted").
			Sensitive().
			Default([]byte("")).
			Comment("用户的手机号码，加密存储"),
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
	return nil
}

// Mixin of the table.
func (Users) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}

// Annotations 自定义表名
func (Users) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_users"},
	}
}
