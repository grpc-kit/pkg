package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Permissions 组下关联的具体用户
type Permissions struct {
	ent.Schema
}

// Fields of the table.
func (Permissions) Fields() []ent.Field {
	return []ent.Field{
		field.Int("resource_id").
			Positive().
			Comment("关联 lion_resources 表的资源 ID"),
		/*
			field.String("name").
				MaxLen(256).
				NotEmpty().
				Comment("对我展示的权限名称，如：管理用户列表"),
			field.String("action").
				MaxLen(256).
				NotEmpty().
				Comment("允许的操作行为，如：create, readonly, update, delete, list, execute, admin"),
			field.String("effect").
				MaxLen(128).
				NotEmpty().
				Comment("权限的行为，如 allow, deny"),
			field.String("description").
				Default("").
				Comment("详细描述"),
		*/
	}
}

// Edges of the table.
func (Permissions) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("lion_role_permissions", RolePermissions.Type),
		edge.From("lion_resources", Resources.Type).
			Ref("lion_permissions").
			Field("resource_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (Permissions) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (Permissions) Indexes() []ent.Index {
	return nil
}

// Annotations 自定义表名
func (Permissions) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_permissions"},
	}
}
