package schema

import (
	"regexp"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Roles holds the schema definition for the Demo entity.
type Roles struct {
	ent.Schema
}

// Fields of the table.
func (Roles) Fields() []ent.Field {
	return []ent.Field{
		field.String("name").
			MaxLen(128).
			NotEmpty().
			Unique().
			Match(regexp.MustCompile(`^[a-zA-Z0-9]+$`)).
			Comment("角色名称，仅支持字母、数字"),
		field.String("i18n_name").
			Default("").
			Comment("国际化标识"),
		field.Bool("protected").
			Default(false).
			Comment("是否保护字段，不允许 UI 修改"),
		field.Int("order_weight").
			Default(0).
			Comment("排序权重，越小越靠前"),
		field.String("description").
			Default("").
			Comment("用途详细描述"),
	}
}

// Edges of the table.
func (Roles) Edges() []ent.Edge {
	return []ent.Edge{
		// 一个 Role 可以对应多个 RoleMenu (中间实体)
		edge.To("lion_role_resources", RoleResources.Type),
		edge.To("lion_user_roles", UserRoles.Type),
		edge.To("lion_role_groups", GroupRoles.Type),
		edge.To("lion_role_departments", RoleDepartments.Type),
	}
}

// Mixin of the table.
func (Roles) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Annotations 自定义表名
func (Roles) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_roles"},
	}
}
