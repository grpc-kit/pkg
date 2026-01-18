package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// Demo holds the schema definition for the Demo entity.
type PermissionsBindings struct {
	ent.Schema
}

// Fields of the table.
func (PermissionsBindings) Fields() []ent.Field {
	return []ent.Field{
		field.Int("permission_id").
			Positive().
			Comment("关联 lion_permissions 表的权限 ID"),
		field.Int("resource_scope_id").
			Positive().
			Comment("关联 lion_resource_scopes 表的资源 ID"),
	}
}

// Edges of the table.
func (PermissionsBindings) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (PermissionsBindings) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Annotations 自定义表名
func (PermissionsBindings) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_permission_bindings"},
	}
}
