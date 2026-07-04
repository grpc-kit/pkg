package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// PrincipalRoles 表示用户、群组、部门到角色的统一绑定关系。
type PrincipalRoles struct {
	ent.Schema
}

// Fields of the table.
func (PrincipalRoles) Fields() []ent.Field {
	return []ent.Field{
		field.Int("principal_type").
			Default(0).
			Comment("主体类型：0-未指定，1-用户，2-群组，3-部门"),
		field.Int("principal_id").
			Positive().
			Comment("主体 ID，与 principal_type 配合使用"),
		field.Int("role_id").
			Positive().
			Comment("角色 ID，关联 lion_roles"),
		field.Int("binding_status").
			Default(1).
			Comment("绑定状态：1-生效，2-禁用"),
		field.Time("expires_at").
			Optional().
			Comment("绑定有效期，空表示永久有效"),
		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("元数据，用于存储来源等扩展属性"),
		field.String("description").
			Default("").
			Comment("绑定关系描述"),
	}
}

// Edges of the table.
func (PrincipalRoles) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lion_roles", Roles.Type).
			Ref("lion_principal_roles").
			Field("role_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (PrincipalRoles) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (PrincipalRoles) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("principal_type", "principal_id", "role_id").Unique(),
		index.Fields("role_id"),
		index.Fields("principal_type", "principal_id"),
		index.Fields("binding_status"),
	}
}

// Annotations 自定义表名。
func (PrincipalRoles) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_principal_roles"},
	}
}
