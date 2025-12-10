package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// ResourceScopes holds the schema definition for the Demo entity.
type ResourceScopes struct {
	ent.Schema
}

// Fields of the table.
func (ResourceScopes) Fields() []ent.Field {
	return []ent.Field{
		field.Int("resource_id").
			Positive().
			// Immutable().
			Comment("关联 lion_resources 表 ID"),
		field.Int("scope_id").
			Positive().
			// Immutable().
			Comment("关联 lion_scopes 表 ID"),
	}
}

// Edges of the table.
func (ResourceScopes) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lion_resources", Resources.Type).
			Ref("lion_resource_scopes").
			Field("resource_id").
			Unique().
			Required(),
		edge.From("lion_scopes", Scopes.Type).
			Ref("lion_resource_scopes").
			Field("scope_id").
			Unique().
			Required(),
		edge.To("lion_permissions", Permissions.Type),
	}
}

// Mixin of the table.
func (ResourceScopes) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Annotations 自定义表名
func (ResourceScopes) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_resource_scopes"},
	}
}
