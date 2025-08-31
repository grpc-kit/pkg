package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// GroupMembership 组下关联的具体用户
type GroupMembership struct {
	ent.Schema
}

// Fields of the table.
func (GroupMembership) Fields() []ent.Field {
	return []ent.Field{
		field.Int("group_id").
			Positive().
			Immutable().
			Comment("关联 lion_groups 表的用户组 ID"),
		field.Int("user_id").
			Positive().
			Immutable().
			Comment("关联 lion_users 表的用户 ID"),
	}
}

// Edges of the table.
func (GroupMembership) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (GroupMembership) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Indexes of the table.
func (GroupMembership) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id", "user_id").Unique(),
	}
}

// Annotations 自定义表名
func (GroupMembership) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_group_membership"},
	}
}