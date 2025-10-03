package schema

import (
	"regexp"
	"time"

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
		field.String("username").
			NotEmpty().
			Unique().
			MaxLen(255).
			Match(regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`)).
			Comment("首选用户名，用于系统识别与登录，仅支持字母、数字、下划线、点号"),
		field.Bytes("realname_encrypted").
			Sensitive().
			Default([]byte{}).
			Comment("用户的真实姓名"),
		field.Int("status").
			Default(0).
			Comment("用户状态"),
		field.Bytes("national_id_encrypted").
			Sensitive().
			Default([]byte{}).
			Comment("用户身份证号码"),
		field.String("national_id_hash").
			Optional().
			Default("").
			Comment("用户的身份证号码哈希，用于唯一值判断"),
		field.String("nickname").
			Default("").
			Comment("用户的昵称，用于页面展示"),
		field.String("profile").
			Default("").
			MaxLen(500).
			Comment("用户个人简介等"),
		field.String("picture").
			Default("").
			Comment("用户头像的 URL"),
		field.String("website").
			Default("").
			Comment("用户的个人网站 URL"),
		field.Bytes("email_encrypted").
			Sensitive().
			Default([]byte{}).
			Comment("用户的邮箱地址"),
		field.String("email_hash").
			Optional().
			Default("").
			Comment("用户的邮箱地址哈希，用于唯一值判断"),
		field.Bool("email_verified").
			Default(false).
			Comment("邮箱是否验证过"),
		field.Int("gender").
			Default(0).
			Comment("用户的性别，如：0, 1=male、2=female"),
		field.Time("birthdate").
			Optional().
			Default(func() time.Time { return time.Time{} }).
			Comment("用户的出生日期，格式为 YYYY-MM-DD，如 1990-12-31"),
		field.String("zoneinfo").
			Default("").
			Comment("用户的时区信息，如：Asia/Shanghai"),
		field.String("locale").
			Default("").
			Comment("用户的语言/地区偏好，如：zh-CN"),
		field.Bytes("phone_number_encrypted").
			Sensitive().
			Default([]byte{}).
			Comment("用户的手机号码，加密存储"),
		field.String("phone_number_hash").
			Optional().
			Default("").
			Comment("用户的手机号哈希，用于唯一值判断"),
		field.Bool("phone_number_verified").
			Default(false).
			Comment("手机号是否验证过"),
		field.Bytes("address_encrypted").
			Sensitive().
			Default([]byte{}).
			Comment("用户的地址信息"),
		field.Int("department_id").
			Default(1).
			Comment("部门 ID"),
		field.String("description").
			Default("").
			MaxLen(4096).
			Comment("用户详细描述"),
	}
}

// Edges of the table.
func (Users) Edges() []ent.Edge {
	return []ent.Edge{
		// 一个 Role 可以对应多个 RoleMenu (中间实体)
		edge.To("lion_user_roles", UserRoles.Type),
		edge.To("lion_user_groups", UserGroups.Type),
		edge.To("lion_user_identities", UserIdentities.Type),
		edge.To("lion_user_departments", UserDepartments.Type),
		edge.From("lion_departments", Departments.Type).
			Ref("lion_users").
			Field("department_id").
			Unique().
			Required(),
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
