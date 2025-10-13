package schema

import (
	"regexp"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
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
			Optional(). // 可选字段
			Comment("用户的真实姓名"),
		field.Int("user_type").
			Default(0).
			Comment("用户类型"),
		field.Int("user_status").
			Default(0).
			Comment("用户状态"),
		field.Bytes("national_id_encrypted").
			Sensitive().
			Optional(). // 可选字段
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
			Optional(). // 可选字段
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
		field.String("timezone").
			Default("").
			Comment("用户的时区信息，如：Asia/Shanghai"),
		field.String("locale").
			Default("").
			Comment("用户的语言/地区偏好，如：zh-CN"),
		field.Bytes("phone_number_encrypted").
			Sensitive().
			Optional(). // 可选字段
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
			Optional(). // 可选字段
			Comment("用户的地址信息"),
		/*
			field.Int("department_id").
				Default(1).
				Comment("部门 ID"),
		*/
		field.String("description").
			Default("").
			MaxLen(4096).
			Comment("用户详细描述"),
		field.JSON("metadata", map[string]string{}).
			Default(map[string]string{}).
			Comment("自定义元数据，用于存储额外的用户信息，对应 proto 中的 map<string, string> metadata"),
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
		/*
			edge.From("lion_departments", Departments.Type).
				Ref("lion_users").
				Field("department_id").
				Unique().
				Required(),
		*/
	}
}

// Mixin of the table.
func (Users) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
		AuditMixin{},
	}
}

// Indexes 定义索引
func (Users) Indexes() []ent.Index {
	return []ent.Index{
		// 用户名唯一索引（已在字段定义中设置 Unique，这里作为补充）
		index.Fields("username").Unique(),
		// 用户类型索引，用于按类型查询用户
		index.Fields("user_type"),
		// 用户状态索引，用于过滤不同状态的用户
		index.Fields("user_status"),
		// 邮箱哈希索引，用于邮箱唯一性检查
		index.Fields("email_hash").Unique(),
		// 手机号哈希索引，用于手机号唯一性检查
		index.Fields("phone_number_hash").Unique(),
		// 身份证号哈希索引，用于身份证号唯一性检查
		index.Fields("national_id_hash").Unique(),
		// 邮箱验证状态索引
		index.Fields("email_verified"),
		// 手机号验证状态索引
		index.Fields("phone_number_verified"),
		// 性别索引，用于统计分析
		index.Fields("gender"),
		// 创建者索引，用于审计查询
		index.Fields("created_by"),
		// 更新者索引，用于审计查询
		index.Fields("updated_by"),
		// 类型和状态组合索引，用于复合查询
		index.Fields("user_type", "user_status"),
		// 创建时间索引，用于时间范围查询
		index.Fields("created_at"),
	}
}

// Annotations 自定义表名
func (Users) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_users"},
	}
}
