package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// Menus holds the schema definition for the Demo entity.
type Menus struct {
	ent.Schema
}

// Fields of the table.
func (Menus) Fields() []ent.Field {
	return []ent.Field{
		field.Int("parent_id").
			Default(0).
			Comment("父菜单 ID，为 0 表示顶级菜单"),
		field.String("name").
			MaxLen(128).
			NotEmpty().
			Comment("菜单名称"),
		field.String("path").
			MaxLen(255).
			NotEmpty().
			Comment("菜单路径"),
		field.String("locale").
			MaxLen(128).
			Default("").
			Comment("国际化标识"),
		field.String("icon").
			MaxLen(256).
			Default("").
			Comment("图标名称，如 UserOutlined"),
		field.Int("sort_weight").
			Default(0).
			Comment("排序权重，越小越靠前"),
		field.Bool("enabled").
			Default(true).
			Comment("是否启用该菜单项，禁用后完全不可访问"),
		field.Bool("hide_in_menu").
			Default(false).
			Comment("是否在菜单中隐藏该节点"),
		field.Bool("hide_children_in").
			Default(false).
			Comment("是否隐藏该节点的子菜单"),
	}
}

// Edges of the table.
func (Menus) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (Menus) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Annotations 自定义表名
func (Menus) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_menus"},
	}
}
