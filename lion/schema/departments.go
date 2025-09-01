package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// Departments 组织架构部门管理
type Departments struct {
	ent.Schema
}

// Fields of the table.
func (Departments) Fields() []ent.Field {
	return []ent.Field{
		field.Int("parent_id").
			Default(0).
			Comment("父菜单 ID，为 0 表示顶级菜单"),
		field.String("name").
			Unique().
			MaxLen(128).
			NotEmpty().
			Comment("部门名称"),
		field.String("i18n_name").
			Comment("多国语言"),
		field.Int("order_weight").
			Default(0).
			Comment("排序权重，越小越靠前"),
	}
}

// Edges of the table.
func (Departments) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (Departments) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Annotations 自定义表名
func (Departments) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_departments"},
	}
}
