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
			Comment("统一动作编码，如：admin.iam:ListUsers"),
		field.String("display_name").
			Default("").
			Comment("动作展示名称"),
		field.Int("resource_type_id").
			Optional().
			Nillable().
			Comment("关联 lion_resource_types 表 ID，可为空（跨类型动作）"),
		field.Bool("protected").
			Default(false).
			Comment("是否系统保护动作，保护动作不可删除"),
		field.String("description").
			Default("").
			Comment("详细描述"),
		field.Int("risk_level").
			Default(0).
			Comment("风险等级：0=low 1=medium 2=high"),
		field.String("output_fields").
			MaxLen(4096).
			Default("[]").
			Comment("动作响应字段全集，JSON 数组，用于字段级权限控制"),
		field.String("enforcement_mode").
			MaxLen(32).
			Default("ENFORCED").
			Comment("执行模式：ENFORCED / SHADOW / DISABLED"),
	}
}

// Edges of the table.
func (Actions) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lion_resource_types", ResourceTypes.Type).
			Ref("lion_actions").
			Field("resource_type_id").
			Unique(),
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
		index.Fields("resource_type_id"),
	}
}

// Annotations 自定义表名
func (Actions) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_actions"},
	}
}
