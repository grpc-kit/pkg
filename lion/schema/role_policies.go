package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// RolePolicies 角色与策略的关联关系。
type RolePolicies struct {
	ent.Schema
}

// Fields of the table.
func (RolePolicies) Fields() []ent.Field {
	return []ent.Field{
		field.Int("role_id").
			Positive().
			Comment("关联 lion_roles 表的角色 ID"),
		field.Int("policy_id").
			Positive().
			Comment("关联 lion_policies 表的策略 ID"),
		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("元数据，用于存储来源等扩展属性"),
		field.String("description").
			Default("").
			Comment("绑定关系描述"),
	}
}

// Edges of the table.
func (RolePolicies) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lion_roles", Roles.Type).
			Ref("lion_role_policies").
			Field("role_id").
			Unique().
			Required(),
		edge.From("lion_policies", Policies.Type).
			Ref("lion_role_policies").
			Field("policy_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (RolePolicies) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (RolePolicies) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("role_id", "policy_id").Unique(),
		index.Fields("role_id"),
		index.Fields("policy_id"),
	}
}

// Annotations 自定义表名
func (RolePolicies) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_role_policies"},
	}
}
