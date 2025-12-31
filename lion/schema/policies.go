package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Policies holds the schema definition for the Policies entity.
type Policies struct {
	ent.Schema
}

// Fields of the table.
func (Policies) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			MaxLen(256).
			NotEmpty().
			Comment("对我展示的权限名称，如：管理用户列表"),
		field.String("display_name").
			NotEmpty().
			Comment("国际化键值，用于前端多语言显示的标识符"),
		field.Int("policy_type").
			Default(0).
			Comment("用途类型，对应 api/known/admin/v1/common.proto 中定义"),
		field.Int("policy_status").
			Default(0).
			Comment("是否启用该资源项，禁用后完全不可访问"),
		field.String("value").
			Default("").
			Comment("策略内容"),
		field.String("description").
			Default("").
			Comment("详细描述"),
	}
}

// Edges of the table.
func (Policies) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("lion_permissions", Permissions.Type),
	}
}

// Mixin of the table.
func (Policies) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
		AuditMixin{},
	}
}

// Annotations 自定义表名
func (Policies) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_policies"},
	}
}
