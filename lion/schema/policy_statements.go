package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// PolicyStatements holds the schema definition for the PolicyStatements entity.
type PolicyStatements struct {
	ent.Schema
}

// Fields of the table.
func (PolicyStatements) Fields() []ent.Field {
	return []ent.Field{
		field.Int("policy_id").
			Positive().
			Comment("关联 lion_policies 表的策略 ID"),
		field.String("sid").
			MaxLen(128).
			NotEmpty().
			Comment("策略语句唯一标识"),
		field.Int("effect").
			Default(0).
			Comment("语句效果：ALLOW 或 DENY"),
		field.String("action_selector").
			Default("").
			Comment("动作选择器，支持 JSON 数组或通配表达式"),
		field.String("resource_selector").
			Default("").
			Comment("资源选择器，支持 JSON 数组或定位表达式"),
		field.String("condition_json").
			Default("").
			Comment("结构化条件 JSON"),
		field.Int("priority").
			Default(0).
			Comment("优先级，数值越小优先级越高"),
		field.String("description").
			Default("").
			Comment("详细描述"),
	}
}

// Edges of the table.
func (PolicyStatements) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lion_policies", Policies.Type).
			Ref("lion_policy_statements").
			Field("policy_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (PolicyStatements) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (PolicyStatements) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("policy_id", "sid").Unique(),
		index.Fields("policy_id", "effect", "priority"),
	}
}

// Annotations 自定义表名
func (PolicyStatements) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_policy_statements"},
	}
}
