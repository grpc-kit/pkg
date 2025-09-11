package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
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
		field.Int("user_id").
			Positive().
			Immutable().
			Comment("关联 lion_users 表的用户 ID"),
		field.Int("group_id").
			Positive().
			Immutable().
			Comment("关联 lion_groups 表的用户组 ID"),
	}
}

// Edges of the table.
func (UserGroups) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (UserGroups) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Indexes of the table.
func (UserGroups) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "group_id").Unique(),
	}
}

// Annotations 自定义表名
func (UserGroups) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_user_groups"},
	}
}
