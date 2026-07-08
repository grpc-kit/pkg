package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// UserProfiles 用于存储用户的扩展属性信息
type UserProfiles struct {
	ent.Schema
}

// Fields of the table.
func (UserProfiles) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id").
			Positive().
			Immutable().
			Comment("用户ID，关联 lion_users 表"),
		field.String("attr_key").
			NotEmpty().
			Comment("属性键"),
		field.String("attr_value").
			NotEmpty().
			Comment("属性值"),
	}
}

// Edges of the table.
func (UserProfiles) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (UserProfiles) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Indexes of the table.
func (UserProfiles) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "attr_key").Unique(),
	}
}

// Annotations 自定义表名
func (UserProfiles) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_user_profiles"},
	}
}
