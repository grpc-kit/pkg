package schema

import (
	"regexp"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

var (
	// URLRegex 验证 URL 格式的正则表达式，支持 http:// 和 https://
	// 匹配格式: http://example.com, https://example.com/path, example.com/path
	URLRegex = regexp.MustCompile(`^(https?://)?([\da-z\.-]+)\.([a-z\.]{2,6})([/\w \.-]*)*/?$`)
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
			Comment("用户的身份证号码哈希，用于唯一值判断"),
		field.String("nickname").
			Optional().
			Comment("用户的昵称，用于页面展示"),
		field.String("profile").
			Optional().
			MaxLen(500).
			Comment("用户个人简介等"),
		field.String("picture").
			Optional().
			Match(URLRegex).
			Comment("用户头像的 URL"),
		field.String("website").
			Optional().
			Match(URLRegex).
			Comment("用户的个人网站 URL"),
		field.Bytes("email_encrypted").
			Sensitive().
			Optional(). // 可选字段
			Comment("用户的邮箱地址"),
		field.String("email_hash").
			Optional().
			Comment("用户的邮箱地址哈希，用于唯一值判断"),
		field.Bool("email_verified").
			Default(false).
			Comment("邮箱是否验证过"),
		field.Int("gender").
			Default(0).
			Range(0, 4).
			Comment("用户的性别：0-未知，1-男性，2-女性，3-其他，4-保密"),
		field.Time("birthdate").
			Optional().
			Nillable().
			Comment("用户的出生日期，格式为 YYYY-MM-DD，如 1990-12-31"),
		field.String("timezone").
			Optional().
			Comment("用户的时区信息，如：Asia/Shanghai"),
		field.String("locale").
			Optional().
			Comment("用户的语言/地区偏好，如：zh-CN"),
		field.Bytes("phone_number_encrypted").
			Sensitive().
			Optional(). // 可选字段
			Comment("用户的手机号码，加密存储"),
		field.String("phone_number_hash").
			Optional().
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
			Optional().
			MaxLen(4096).
			Comment("用户详细描述"),
		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("自定义元数据，用于存储额外的用户信息，对应 proto 中的 map<string, string> metadata"),
	}
}

// Edges of the table.
func (Users) Edges() []ent.Edge {
	return []ent.Edge{
		// 一个 Role 可以对应多个 RoleMenu (中间实体)
		edge.To("lion_user_roles", UserRoles.Type),
		edge.To("lion_user_memberships", UserMemberships.Type),
		edge.To("lion_user_identities", UserIdentities.Type),
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
// 索引策略说明：
// 1. 单字段索引：保留高频单独使用的字段（user_type, user_status）
// 2. 组合索引：根据实际查询模式优化，遵循最左前缀原则
// 3. 唯一索引：哈希字段使用条件唯一索引（仅非空值唯一）
// 4. 查询模式：通常过滤 deleted_at IS NULL + user_status/user_type + 按 created_at 排序
func (Users) Indexes() []ent.Index {
	return []ent.Index{
		// 用户名唯一索引已在字段定义中设置 Unique()，无需重复定义

		// === 唯一性约束索引（条件唯一，仅非空值）===
		// 邮箱哈希唯一索引，用于邮箱唯一性检查（非空值唯一）
		index.Fields("email_hash").Unique().Annotations(
			entsql.IndexWhere("email_hash != '' AND email_hash IS NOT NULL"),
		),
		// 手机号哈希唯一索引，用于手机号唯一性检查（非空值唯一）
		index.Fields("phone_number_hash").Unique().Annotations(
			entsql.IndexWhere("phone_number_hash != '' AND phone_number_hash IS NOT NULL"),
		),
		// 身份证号哈希唯一索引，用于身份证号唯一性检查（非空值唯一）
		index.Fields("national_id_hash").Unique().Annotations(
			entsql.IndexWhere("national_id_hash != '' AND national_id_hash IS NOT NULL"),
		),

		// === 高频查询组合索引（按使用频率排序）===
		// 最常用：软删除 + 状态 + 创建时间（用于列表查询和排序）
		index.Fields("deleted_at", "user_status", "created_at"),
		// 次常用：软删除 + 类型 + 状态 + 创建时间（复合过滤查询）
		index.Fields("deleted_at", "user_type", "user_status", "created_at"),
		// 通用：软删除 + 创建时间（时间范围查询和排序）
		index.Fields("deleted_at", "created_at"),
		// 类型和状态组合索引（不涉及软删除的查询）
		index.Fields("user_type", "user_status"),
		// 类型和创建时间（按类型统计和查询）
		index.Fields("user_type", "created_at"),

		// === 单字段索引（高频单独使用）===
		// 用户类型索引，用于按类型查询用户（保留，因为可能单独使用）
		index.Fields("user_type"),
		// 用户状态索引，用于过滤不同状态的用户（保留，因为可能单独使用）
		index.Fields("user_status"),

		// === 验证状态相关索引 ===
		// 邮箱哈希和验证状态组合索引，用于验证状态查询（邮箱存在且已验证）
		index.Fields("email_hash", "email_verified").Annotations(
			entsql.IndexWhere("email_hash != '' AND email_hash IS NOT NULL"),
		),
		// 手机号哈希和验证状态组合索引，用于验证状态查询（手机号存在且已验证）
		index.Fields("phone_number_hash", "phone_number_verified").Annotations(
			entsql.IndexWhere("phone_number_hash != '' AND phone_number_hash IS NOT NULL"),
		),

		// === 审计和时间查询索引 ===
		// 创建时间索引，用于时间范围查询（单字段查询场景）
		index.Fields("created_at"),
		// 审计查询：创建者和创建时间组合索引
		index.Fields("created_by", "created_at"),
		// 更新者和更新时间组合索引（用于追踪修改记录）
		index.Fields("updated_by", "updated_at"),
	}
}

// Annotations 自定义表名
func (Users) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_users"},
	}
}
