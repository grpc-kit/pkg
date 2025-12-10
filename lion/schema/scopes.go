package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Scopes holds the schema definition for the Demo entity.
type Scopes struct {
	ent.Schema
}

// Fields of the table.
func (Scopes) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			Unique().
			MaxLen(128).
			NotEmpty().
			Comment("名称"),
		field.String("display_name").
			Default("").
			Comment("友好展示名称"),
	}
}

// Edges of the table.
func (Scopes) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("lion_resource_scopes", ResourceScopes.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Mixin of the table.
func (Scopes) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Annotations 自定义表名
func (Scopes) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_scopes"},
	}
}
