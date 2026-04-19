package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
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
			Comment("对应 api/known/admin/v1/admin.common.proto 中的 Resource.Type"),
		field.String("projection_mapping").
			MaxLen(4096).
			Default("{}").
			Comment("协议映射配置（JSON），描述动作在 HTTP/gRPC/Event/MCP 等协议下的投影方式"),
		field.Bool("protected").
			Default(false).
			Comment("是否系统保护动作，保护动作不可删除"),
		field.String("description").
			Default("").
			Comment("详细描述"),
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
	}
}

// Annotations 自定义表名
func (Actions) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_actions"},
	}
}
