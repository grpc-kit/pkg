package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
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
	return nil
}

// Mixin of the table.
func (RolePermissions) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Annotations 自定义表名
func (RolePermissions) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_role_permissions"},
	}
}
