package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// Accounts 账户表 | 存储账户信息，通常与用户相关联
type Accounts struct {
	ent.Schema
}

// Fields of the table.
func (Accounts) Fields() []ent.Field {
	return []ent.Field{
		field.Float("balance").Default(0),
		field.String("currency").Default("CNY"),
	}
}

// Edges of the table.
func (Accounts) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (Accounts) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Annotations 自定义表名
func (Accounts) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_accounts"},
	}
}
