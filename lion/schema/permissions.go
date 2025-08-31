package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// Permissions 组下关联的具体用户
type Permissions struct {
	ent.Schema
}

// Fields of the table.
func (Permissions) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			MaxLen(256).
			NotEmpty().
			Comment("权限名称"),
	}
}

// Edges of the table.
func (Permissions) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (Permissions) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Indexes of the table.
func (Permissions) Indexes() []ent.Index {
	return nil
}

// Annotations 自定义表名
func (Permissions) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_permissions"},
	}
}
