package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// PolicyAttachments holds the schema definition for the PolicyAttachments entity.
type PolicyAttachments struct {
	ent.Schema
}

// Fields of the table.
func (PolicyAttachments) Fields() []ent.Field {
	return []ent.Field{
		field.Int("policy_id").
			Positive().
			Comment("关联 lion_policies 表的策略 ID"),
		field.String("principal_type").
			MaxLen(32).
			Default("").
			Comment("主体类型：user / role / group / department 等"),
		field.Int64("principal_id").
			Default(0).
			Comment("主体 ID"),
		field.Int64("resource_id").
			Default(0).
			Comment("资源 ID，可选"),
		field.Bool("is_recursive").
			Default(false).
			Comment("是否递归作用于子资源或子节点"),
		field.Int("attachment_status").
			Default(0).
			Comment("挂载状态"),
		field.String("condition_json").
			Default("").
			Comment("挂载附加条件 JSON"),
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("过期时间"),
		field.String("description").
			Default("").
			Comment("详细描述"),
	}
}

// Edges of the table.
func (PolicyAttachments) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lion_policies", Policies.Type).
			Ref("lion_policy_attachments").
			Field("policy_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (PolicyAttachments) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (PolicyAttachments) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("policy_id", "principal_type", "principal_id"),
		index.Fields("principal_type", "principal_id", "attachment_status"),
		index.Fields("resource_id"),
	}
}

// Annotations 自定义表名
func (PolicyAttachments) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_policy_attachments"},
	}
}
