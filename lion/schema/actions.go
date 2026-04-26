package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Actions holds the schema definition for the Actions entity.
type Actions struct {
	ent.Schema
}

// Fields of the table.
func (Actions) Fields() []ent.Field {
	return []ent.Field{
		field.String("code").
			MaxLen(128).
			NotEmpty().
			Comment("统一动作编码，如：admin.users.read"),
		field.String("display_name").
			Default("").
			Comment("动作展示名称"),
		field.Int("resource_type").
			Default(0).
			Comment("兼容期保留的旧资源类型枚举字段"),
		field.Int("resource_type_id").
			Positive().
			Comment("关联 lion_resource_types 表 ID"),
		field.String("projection_mapping").
			MaxLen(4096).
			Default("{}").
			Comment("兼容期保留的协议映射配置"),
		field.Bool("protected").
			Default(false).
			Comment("是否系统保护动作，保护动作不可删除"),
		field.String("description").
			Default("").
			Comment("详细描述"),
	}
}

// Edges of the table.
func (Actions) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lion_resource_types", ResourceTypes.Type).
			Ref("lion_actions").
			Field("resource_type_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (Actions) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (Actions) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("code").Unique(),
		index.Fields("resource_type"),
		index.Fields("resource_type_id"),
	}
}

// Annotations 自定义表名
func (Actions) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_actions"},
	}
}
