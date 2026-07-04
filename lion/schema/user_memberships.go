package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// UserMemberships 表示用户到群组/部门的统一静态归属关系。
type UserMemberships struct {
	ent.Schema
}

// Fields of the table.
func (UserMemberships) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id").
			Positive().
			Comment("用户 ID，关联用户表"),
		field.Int("target_type").
			Default(0).
			Comment("关联目标类型：0-未指定，1-群组，2-部门"),
		field.Int("target_id").
			Positive().
			Comment("关联目标 ID，与 target_type 配合使用"),
		field.Int("member_role").
			Default(0).
			Comment("用户在目标实体中的角色：兼容群组/部门成员角色枚举"),
		field.Int("member_status").
			Default(0).
			Comment("成员关系状态：兼容群组/部门成员状态枚举"),
		field.Int("member_type").
			Default(0).
			Comment("成员关系类型：主要用于部门主/兼职语义"),
		field.Time("joined_at").
			Optional().
			Comment("用户加入目标实体的时间"),
		field.Time("expires_at").
			Optional().
			Comment("关系有效期，用于临时成员管理，空表示永久有效"),
		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("元数据，用于存储自定义属性，统一采用 JSON"),
		field.String("description").
			Default("").
			Comment("成员关系描述"),
	}
}

// Edges of the table.
func (UserMemberships) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lion_users", Users.Type).
			Ref("lion_user_memberships").
			Field("user_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (UserMemberships) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (UserMemberships) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "target_type", "target_id").Unique(),
		index.Fields("target_type", "target_id"),
		// index.Fields("user_id"),
		index.Fields("user_id").
			Unique().
			Annotations(entsql.IndexWhere("target_type = 2 AND member_type = 1")),
	}
}

// Annotations 自定义表名。
func (UserMemberships) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_user_memberships"},
	}
}
