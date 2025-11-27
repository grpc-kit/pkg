package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// ResourceUris holds the schema definition for the Demo entity.
type ResourceUris struct {
	ent.Schema
}

// Fields of the table.
func (ResourceUris) Fields() []ent.Field {
	return []ent.Field{
		field.Int("resource_id").
			Positive().
			// Immutable().
			Comment("关联 lion_resources 表 ID"),
		field.String("uri").
			NotEmpty().
			Comment("资源地址"),
	}
}

// Edges of the table.
func (ResourceUris) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (ResourceUris) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Annotations 自定义表名
func (ResourceUris) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_resource_uris"},
	}
}
