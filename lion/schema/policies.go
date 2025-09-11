package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// Policies holds the schema definition for the Policies entity.
type Policies struct {
	ent.Schema
}

// Fields of the table.
func (Policies) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").Default("grpc-kit"),
	}
}

// Edges of the table.
func (Policies) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (Policies) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Annotations 自定义表名
func (Policies) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_policies"},
	}
}
