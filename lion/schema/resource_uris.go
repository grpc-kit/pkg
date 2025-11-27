package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
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
		field.String("path").
			MaxLen(512).
			Default("").
			Comment("资源路径"),
		field.Bool("hidden").
			Default(false).
			Comment("是否在资源列表中隐藏该节点"),
		field.Bool("hide_children").
			Default(false).
			Comment("是否隐藏该资源节点的子项"),
		field.String("icon").
			MaxLen(256).
			Default("").
			Comment("图标名称，如 UserOutlined"),
		field.String("component").
			MaxLen(256).
			Default("").
			Comment("组件名称，如 UserOutlined"),
		field.String("description").
			Default("").
			Comment("详细描述"),
	}
}

// Edges of the table.
func (ResourceUris) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lion_resources", Resources.Type).
			Ref("lion_resource_uris").
			Field("resource_id").
			Unique().
			Required(),
	}
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
