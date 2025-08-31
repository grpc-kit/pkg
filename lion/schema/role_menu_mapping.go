package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// RoleMenuMapping 角色关联的菜单项
type RoleMenuMapping struct {
	ent.Schema
}

// Fields of the table.
func (RoleMenuMapping) Fields() []ent.Field {
	return []ent.Field{
		field.Int("role_id").
			Positive().
			// Immutable().
			Comment("关联 lion_role 表的用户组 ID"),
		field.Int("menu_id").
			Positive().
			// Immutable().
			Comment("关联 lion_menus 表的菜单 ID"),
	}
}

// Edges of the table.
func (RoleMenuMapping) Edges() []ent.Edge {
	return []ent.Edge{
		// 每条 RoleMenu 记录必须属于一个 Role
		edge.From("lion_roles", Roles.Type).
			Ref("lion_role_menus"). // 与 Role 实体中的 edge.To("role_menus", ...) 的 Ref 名称对应
			Field("role_id"). // 明确外键字段名（可选，但推荐显式声明）
			Unique(). // 一条 RoleMenu 记录只属于一个 Role
			Required(),
		// 每条 RoleMenu 记录必须属于一个 Menu
		edge.From("lion_menus", Menus.Type).
			Ref("lion_role_menus").
			Field("menu_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (RoleMenuMapping) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Indexes of the table.
func (RoleMenuMapping) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("role_id", "menu_id").Unique(),
	}
}

// Annotations 自定义表名
func (RoleMenuMapping) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_role_menu_mapping"},
	}
}
