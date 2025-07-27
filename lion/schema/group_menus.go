package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// GroupMenus 组下关联的具体用户
type GroupMenus struct {
	ent.Schema
}

// Fields of the table.
func (GroupMenus) Fields() []ent.Field {
	return []ent.Field{
		field.Int("group_id").
			Positive().
			Immutable().
			Comment("关联 lion_groups 表的用户组 ID"),
		field.Int("menu_id").
			Positive().
			Immutable().
			Comment("关联 lion_menus 表的菜单 ID"),
	}
}

// Edges of the table.
func (GroupMenus) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (GroupMenus) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Indexes of the table.
func (GroupMenus) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("group_id", "menu_id").Unique(),
	}
}

// Annotations 自定义表名
func (GroupMenus) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_group_menus"},
	}
}
