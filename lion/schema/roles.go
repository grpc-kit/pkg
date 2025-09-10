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
		field.String("description").
			Default("").
			Comment("用途详细描述"),
	}
}

// Edges of the table.
func (Roles) Edges() []ent.Edge {
	return []ent.Edge{
		// 一个 Role 可以对应多个 RoleMenu (中间实体)
		edge.To("lion_role_menus", RoleMenus.Type),
		edge.To("lion_role_users", RoleUsers.Type),
		edge.To("lion_role_groups", RoleGroups.Type),
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
