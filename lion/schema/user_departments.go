package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// UserDepartments holds the schema definition for the Demo entity.
type UserDepartments struct {
	ent.Schema
}

// Fields of the table.
func (UserDepartments) Fields() []ent.Field {
	return []ent.Field{
		field.Int("department_id").
			Comment("部门 ID"),
		field.Int("user_id").
			Comment("用户 ID"),
		field.Int("member_role").
			Default(0).
			Comment("用户在群组中的角色：0-未指定，1-所有者，2-管理员，3-普通成员，4-访客"),
		field.Int("member_status").
			Default(0).
			Comment("用户群组关系状态：0-未知状态，1-待激活，2-正常启用，3-被邀请，4-禁用，5-被拒绝，6-已退出"),
		field.Int("member_type").
			Default(0).
			Comment("成员关系类型，区分主部门和兼职部门"),
		field.Time("expired_at").
			Optional().
			Comment("关系有效期，用于临时成员管理，0表示永久有效"),
		field.String("metadata").
			Optional().
			Comment("元数据，用于存储自定义属性，支持业务扩展，JSON 格式存储"),
		field.String("description").
			Default("").
			Comment("用户组描述"),
	}
}

// Edges of the table.
func (UserDepartments) Edges() []ent.Edge {
	return []ent.Edge{
		// 一个 Menu 可以对应多个 RoleMenu (中间实体)
		edge.From("lion_departments", Departments.Type).
			Ref("lion_user_departments").
			Field("department_id").
			Unique().
			Required(),
		edge.From("lion_users", Users.Type).
			Ref("lion_user_departments").
			Field("user_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (UserDepartments) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (UserDepartments) Indexes() []ent.Index {
	return []ent.Index{
		// 确保用户和部门的组合是唯一的
		index.Fields("user_id", "department_id").Unique(),
		// 确保一个用户只能有一个主部门（TYPE_PRIMARY = 1）
		// 这个索引只对 member_type = 1 的记录生效，实现条件唯一约束
		index.Fields("user_id").
			Unique().
			Annotations(entsql.IndexWhere("member_type = 1")),
	}
}

// Annotations 自定义表名
func (UserDepartments) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_user_departments"},
	}
}
