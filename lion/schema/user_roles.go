package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// UserRoles 角色与用户的关系
type UserRoles struct {
	ent.Schema
}

// Fields of the table.
func (UserRoles) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id").
			Positive().
			// Immutable().
			Comment("关联 lion_users 表的菜单 ID"),
		field.Int("role_id").
			Positive().
			// Immutable().
			Comment("关联 lion_roles 表的用户组 ID"),
		field.Int("member_role").
			Default(0).
			Comment("用户在群组中的角色：0-未指定，1-所有者，2-管理员，3-普通成员，4-访客"),
		field.Int("member_status").
			Default(0).
			Comment("用户群组关系状态：0-未知状态，1-待激活，2-正常启用，3-被邀请，4-禁用，5-被拒绝，6-已退出"),
		field.Int("member_type").
			Default(0).
			Comment("成员关系类型，区分主部门和兼职部门"),
		field.Time("expired_at").
			Optional().
			Comment("关系有效期，用于临时成员管理，0表示永久有效"),
		field.String("metadata").
			Optional().
			Comment("元数据，用于存储自定义属性，支持业务扩展，JSON 格式存储"),
		field.String("description").
			Default("").
			Comment("用户组描述"),
	}
}

// Edges of the table.
func (UserRoles) Edges() []ent.Edge {
	return []ent.Edge{
		// 每条 RoleMenu 记录必须属于一个 Menu
		edge.From("lion_users", Users.Type).
			Ref("lion_user_roles").
			Field("user_id").
			Unique().
			Required(),
		// 每条 RoleMenu 记录必须属于一个 Role
		edge.From("lion_roles", Roles.Type).
			Ref("lion_user_roles"). // 与 Role 实体中的 edge.To("role_menus", ...) 的 Ref 名称对应
			Field("role_id").       // 明确外键字段名（可选，但推荐显式声明）
			Unique().               // 一条 RoleMenu 记录只属于一个 Role
			Required(),
	}
}

// Mixin of the table.
func (UserRoles) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (UserRoles) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "role_id").Unique(),
	}
}

// Annotations 自定义表名
func (UserRoles) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_user_roles"},
	}
}
