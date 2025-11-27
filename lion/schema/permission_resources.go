package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// PermissionResources holds the schema definition for the Demo entity.
type PermissionResources struct {
	ent.Schema
}

// Fields of the table.
func (PermissionResources) Fields() []ent.Field {
	return []ent.Field{
		field.Int("permission_id").
			Positive().
			Comment("关联 lion_permissions 表 ID"),
		field.Int("resource_id").
			Positive().
			Comment("关联 lion_resources 表 ID"),
	}
}

// Edges of the table.
func (PermissionResources) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (PermissionResources) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Annotations 自定义表名
func (PermissionResources) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_permission_resources"},
	}
}
