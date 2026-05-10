package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// RoleMenus 角色与菜单的关联关系
type RoleMenus struct {
	ent.Schema
}

// Fields of the table.
func (RoleMenus) Fields() []ent.Field {
	return []ent.Field{
		field.Int("role_id").
			Positive().
			Comment("关联 lion_roles 表的角色 ID"),
		field.Int("menu_id").
			Positive().
			Comment("关联 lion_menus 表的菜单 ID"),
		field.Int("permission_scope").
			Default(1).
			Comment("权限范围：1=可见，2=可操作（如按钮级权限）"),
		field.String("description").
			Default("").
			Comment("描述"),
		field.Bool("is_recursive").
			Default(false).
			Comment("是否递归包含子菜单，为 true 时授权逻辑自动涵盖所有后代菜单"),
	}
}

// Edges of the table.
func (RoleMenus) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lion_roles", Roles.Type).
			Ref("lion_role_menus").
			Field("role_id").
			Unique().
			Required(),
		edge.From("lion_menus", Menus.Type).
			Ref("lion_role_menus").
			Field("menu_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (RoleMenus) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (RoleMenus) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("role_id", "menu_id").Unique(),
		index.Fields("menu_id"),
	}
}

// Annotations 自定义表名
func (RoleMenus) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_role_menus"},
	}
}
