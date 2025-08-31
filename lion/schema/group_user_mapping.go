package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// GroupUserMapping 组下关联的具体用户
type GroupUserMapping struct {
	ent.Schema
}

// Fields of the table.
func (GroupUserMapping) Fields() []ent.Field {
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
func (GroupUserMapping) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (GroupUserMapping) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Indexes of the table.
func (GroupUserMapping) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id", "user_id").Unique(),
	}
}

// Annotations 自定义表名
func (GroupUserMapping) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_group_user_mapping"},
	}
}
