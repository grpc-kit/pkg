package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// UserGroups 组下关联的具体用户
type UserGroups struct {
	ent.Schema
}

// Fields of the table.
func (UserGroups) Fields() []ent.Field {
	return []ent.Field{
		field.Int("id").
			Positive().
			Unique().
			Comment("用户群组关系 ID，全局唯一标识"),
		field.Int("user_id").
			Positive().
			Comment("用户 ID，关联用户表"),
		field.Int("group_id").
			Positive().
			Comment("群组 ID，关联群组表"),
		field.Int("member_role").
			Default(0).
			Comment("用户在群组中的角色：0-未指定，1-所有者，2-管理员，3-普通成员，4-访客"),
		field.Int("member_status").
			Default(0).
			Comment("用户群组关系状态：0-未知状态，1-待激活，2-正常启用，3-被邀请，4-禁用，5-被拒绝，6-已退出"),
		field.Time("joined_at").
			Optional().
			Comment("用户加入群组的时间"),
		field.Time("expired_at").
			Optional().
			Comment("关系有效期，用于临时成员管理，0表示永久有效"),
		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("元数据，用于存储自定义属性，支持业务扩展"),
		field.String("description").
			Default("").
			Comment("用户组描述"),
	}
}

// Edges of the table.
func (UserGroups) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lion_users", Users.Type).
			Ref("lion_user_groups").
			Field("user_id").
			Unique().
			Required(),
		edge.From("lion_groups", Groups.Type).
			Ref("lion_user_groups").
			Field("group_id").
			Unique().
			Required(),
	}
}

// Mixin of the table.
func (UserGroups) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{}, // 使用包含 deleted_at 的 TimeMixin 支持软删除
		AuditMixin{},
	}
}

// Indexes of the table.
func (UserGroups) Indexes() []ent.Index {
	return []ent.Index{
		// 唯一索引：确保用户在同一群组中只有一个关系记录
		index.Fields("user_id", "group_id").Unique(),
	}
}

// Annotations 自定义表名
func (UserGroups) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_user_groups"},
	}
}
