package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// UserAttributes 用于存储用户的扩展属性信息
type UserAttributes struct {
	ent.Schema
}

// Fields of the table.
func (UserAttributes) Fields() []ent.Field {
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
func (UserAttributes) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (UserAttributes) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Indexes of the table.
func (UserAttributes) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id", "attr_key").Unique(),
	}
}

// Annotations 自定义表名
func (UserAttributes) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_user_attributes"},
	}
}
