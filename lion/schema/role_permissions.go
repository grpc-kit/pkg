package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// RolePermissions holds the schema definition for the RolePermissions entity.
type RolePermissions struct {
	ent.Schema
}

// Fields of the table.
func (RolePermissions) Fields() []ent.Field {
	return []ent.Field{
		field.Int("role_id").
			Positive().
			// Immutable().
			Comment("关联 lion_roles 表的角色 ID"),
		field.Int("permission_id").
			Positive().
			// Immutable().
			Comment("关联 lion_permissions 表的菜单 ID"),
	}
}

// Edges of the table.
func (RolePermissions) Edges() []ent.Edge {
	return []ent.Edge{
		// 每条 RoleMenu 记录必须属于一个 Role
		edge.From("lion_roles", Roles.Type).
			Ref("lion_role_permissions"). // 与 Role 实体中的 edge.To("role_resources", ...) 的 Ref 名称对应
			Field("role_id").             // 明确外键字段名（可选，但推荐显式声明）
			Unique().                     // 一条 RoleMenu 记录只属于一个 Role
			Required(),
		// 每条 RoleMenu 记录必须属于一个 Menu
		edge.From("lion_permissions", Permissions.Type).
			Ref("lion_role_permissions").
			Field("permission_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (RolePermissions) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (RolePermissions) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("role_id", "permission_id").Unique(),
	}
}

// Annotations 自定义表名
func (RolePermissions) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_role_permissions"},
	}
}
