package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
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
		field.Int("leader_type").
			Comment("负责人类型"),
		field.Int("user_id").
			Comment("用户 ID"),
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
		edge.From("lion_user_departments", Users.Type).
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
	}
}

// Annotations 自定义表名
func (UserDepartments) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_user_departments"},
	}
}
