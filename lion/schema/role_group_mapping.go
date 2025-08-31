package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// RoleGroupMapping 角色与用户组的关系
type RoleGroupMapping struct {
	ent.Schema
}

// Fields of the table.
func (RoleGroupMapping) Fields() []ent.Field {
	return []ent.Field{
		field.Int("role_id").
			Positive().
			// Immutable().
			Comment("关联 lion_roles 表的用户组 ID"),
		field.Int("group_id").
			Positive().
			// Immutable().
			Comment("关联 lion_groups 表的菜单 ID"),
	}
}

// Edges of the table.
func (RoleGroupMapping) Edges() []ent.Edge {
	return []ent.Edge{
		// 每条 RoleMenu 记录必须属于一个 Role
		edge.From("lion_roles", Roles.Type).
			Ref("lion_role_groups"). // 与 Role 实体中的 edge.To("role_menus", ...) 的 Ref 名称对应
			Field("role_id").        // 明确外键字段名（可选，但推荐显式声明）
			Unique().                // 一条 RoleMenu 记录只属于一个 Role
			Required(),
		// 每条 RoleMenu 记录必须属于一个 Menu
		edge.From("lion_groups", Groups.Type).
			Ref("lion_groups").
			Field("group_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (RoleGroupMapping) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Indexes of the table.
func (RoleGroupMapping) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("role_id", "group_id").Unique(),
	}
}

// Annotations 自定义表名
func (RoleGroupMapping) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_role_group_mapping"},
	}
}
