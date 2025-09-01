package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// DepartmentLeaders holds the schema definition for the Demo entity.
type DepartmentLeaders struct {
	ent.Schema
}

// Fields of the table.
func (DepartmentLeaders) Fields() []ent.Field {
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
func (DepartmentLeaders) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (DepartmentLeaders) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Annotations 自定义表名
func (DepartmentLeaders) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_department_leaders"},
	}
}
