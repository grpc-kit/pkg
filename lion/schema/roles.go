package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Roles holds the schema definition for the Demo entity.
type Roles struct {
	ent.Schema
}

// Fields of the table.
func (Roles) Fields() []ent.Field {
	return []ent.Field{
		field.Int("parent_id").
			Default(0).
			Comment("父角色ID，构建树形组织结构，值为 0 表示顶级角色"),
		field.String("code").
			MaxLen(256).
			NotEmpty().
			Comment("角色名称，用于系统内部显示和业务逻辑"),
		field.String("display_name").
			MaxLen(256).
			NotEmpty().
			Comment("角色名称，用于系统内部显示和业务逻辑"),

		field.Int("role_type").
			Default(0).
			Comment("角色类型：TYPE_SYSTEM=系统内置角色，TYPE_CUSTOM=自定义角色，TYPE_TEMPLATE=模板角色"),
		field.Int("role_status").
			Default(0).
			Comment("角色状态：STATUS_ACTIVE=正常启用，STATUS_DISABLED=禁用状态"),
		field.Int("sort_order").
			Default(100).
			Comment("角色排序顺序，用于同级角色的显示顺序，数值越小排序越靠前，建议使用 10 的倍数便于后续插入，默认值：100，范围：1-9999"),
		field.String("description").
			Default("").
			Comment("用途详细描述"),
	}
}

// Edges of the table.
func (Roles) Edges() []ent.Edge {
	return []ent.Edge{
		// 一个 Role 可以对应多个 RoleMenu (中间实体)
		edge.To("lion_role_permissions", RolePermissions.Type),
		edge.To("lion_user_roles", UserRoles.Type),
		edge.To("lion_role_groups", GroupRoles.Type),
		edge.To("lion_role_data_scopes", RoleDataScopes.Type),
	}
}

// Mixin of the table.
func (Roles) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
		AuditMixin{},
	}
}

// Indexes 定义索引
func (Roles) Indexes() []ent.Index {
	return []ent.Index{
		// 角色名称唯一索引（已在字段定义中设置 Unique，这里作为补充）
		index.Fields("code").Unique(),
	}
}

// Annotations 自定义表名
func (Roles) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_roles"},
	}
}
