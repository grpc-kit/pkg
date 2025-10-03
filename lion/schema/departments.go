package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Departments 组织架构部门管理
type Departments struct {
	ent.Schema
}

// Fields of the table.
func (Departments) Fields() []ent.Field {
	return []ent.Field{
		field.Int("parent_id").
			Default(0).
			Comment("父菜单 ID，为 0 表示顶级菜单"),
		field.String("name").
			MaxLen(128).
			NotEmpty().
			Comment("部门名称"),
		field.String("i18n_name").
			Default("").
			Comment("多国语言"),
		field.Int("order_weight").
			Default(0).
			Comment("排序权重，越小越靠前"),
		field.String("description").
			Default("").
			Comment("详细描述"),
	}
}

// Edges of the table.
func (Departments) Edges() []ent.Edge {
	return []ent.Edge{
		// 一个 Menu 可以对应多个 RoleMenu (中间实体)
		edge.To("lion_users", Users.Type),
		edge.To("lion_role_departments", RoleDepartments.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
		edge.To("lion_user_departments", UserDepartments.Type),
		edge.To("lion_groups", Groups.Type),
	}
}

// Mixin of the table.
func (Departments) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Annotations 自定义表名
func (Departments) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_departments"},
	}
}
