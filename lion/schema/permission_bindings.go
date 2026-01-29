package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// PermissionBindings holds the schema definition for the Demo entity.
type PermissionBindings struct {
	ent.Schema
}

// Fields of the table.
func (PermissionBindings) Fields() []ent.Field {
	return []ent.Field{
		field.Int("permission_id").
			Positive().
			Comment("关联 lion_permissions 表的权限 ID"),
		field.Int("resource_scope_id").
			Positive().
			Comment("关联 lion_resource_scopes 表的资源 ID"),
		field.Bool("is_recursive").
			Default(false).
			Comment("是否递归"),
	}
}

// Edges of the table.
func (PermissionBindings) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lion_permissions", Permissions.Type).
			Ref("lion_permission_bindings").
			Field("permission_id").
			Unique().
			Required(),
		edge.From("lion_resource_scopes", ResourceScopes.Type).
			Ref("lion_permission_bindings").
			Field("resource_scope_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (PermissionBindings) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Annotations 自定义表名
func (PermissionBindings) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_permission_bindings"},
	}
}
