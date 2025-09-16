package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// RoleDepartments 角色关联的菜单项
type RoleDepartments struct {
	ent.Schema
}

// Fields of the table.
func (RoleDepartments) Fields() []ent.Field {
	return []ent.Field{
		field.Int("role_id").
			Positive().
			// Immutable().
			Comment("关联 lion_role 表的用户组 ID"),
		field.Int("department_id").
			Positive().
			// Immutable().
			Comment("关联 lion_departments 表的资源 ID"),
	}
}

// Edges of the table.
func (RoleDepartments) Edges() []ent.Edge {
	return []ent.Edge{
		// 每条 RoleMenu 记录必须属于一个 Role
		edge.From("lion_roles", Roles.Type).
			Ref("lion_role_departments"). // 与 Role 实体中的 edge.To("role_resources", ...) 的 Ref 名称对应
			Field("role_id").             // 明确外键字段名（可选，但推荐显式声明）
			Unique().                     // 一条 RoleMenu 记录只属于一个 Role
			Required(),
		// 每条 RoleMenu 记录必须属于一个 Menu
		edge.From("lion_departments", Departments.Type).
			Ref("lion_role_departments").
			Field("department_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (RoleDepartments) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Indexes of the table.
func (RoleDepartments) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("role_id", "department_id").Unique(),
	}
}

// Annotations 自定义表名
func (RoleDepartments) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_role_departments"},
	}
}
