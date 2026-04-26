package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// ResourceTypes holds the schema definition for the ResourceTypes entity.
type ResourceTypes struct {
	ent.Schema
}

// Fields of the table.
func (ResourceTypes) Fields() []ent.Field {
	return []ent.Field{
		field.String("code").
			MaxLen(64).
			NotEmpty().
			Comment("资源类型编码，如 sys_menu / sys_api"),
		field.String("display_name").
			Default("").
			Comment("资源类型展示名称"),
		field.String("service_code").
			MaxLen(64).
			Default("").
			Comment("归属服务代码，对应 lion_services.code"),
		field.String("description").
			Default("").
			Comment("详细描述"),
		field.Bool("protected").
			Default(false).
			Comment("是否系统保护资源类型"),
	}
}

// Edges of the table.
func (ResourceTypes) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("lion_resources", Resources.Type),
		edge.To("lion_actions", Actions.Type),
	}
}

// Mixin of the table.
func (ResourceTypes) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (ResourceTypes) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("code").Unique(),
		index.Fields("service_code"),
	}
}

// Annotations 自定义表名
func (ResourceTypes) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_resource_types"},
	}
}