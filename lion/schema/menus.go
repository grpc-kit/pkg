package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Menus holds the schema definition for the Menus entity.
type Menus struct {
	ent.Schema
}

// Fields of the table.
func (Menus) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("parent_id").
			Default(0).
			Comment("父菜单 ID，为 0 表示顶级菜单"),
		field.String("code").
			MaxLen(128).
			NotEmpty().
			Comment("菜单代码"),
		field.String("display_name").
			MaxLen(64).
			Default("").
			Comment("菜单展示名称"),
		field.String("route_path").
			MaxLen(255).
			Default("").
			Comment("前端路由路径"),
		field.String("component").
			MaxLen(255).
			Default("").
			Comment("前端组件名"),
		field.String("icon").
			MaxLen(64).
			Default("").
			Comment("图标名称"),
		field.Int("sort_order").
			Default(100).
			Comment("菜单排序顺序"),
		field.String("visibility").
			MaxLen(16).
			Default("full").
			Comment("菜单可见性"),
		field.String("menu_status").
			MaxLen(16).
			Default("active").
			Comment("菜单状态"),
		field.JSON("metadata", map[string]any{}).
			Optional().
			Comment("前端元数据"),
		field.String("description").
			Default("").
			Comment("详细描述"),
	}
}

// Edges of the table.
func (Menus) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("lion_role_menus", RoleMenus.Type),
	}
}

// Mixin of the table.
func (Menus) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (Menus) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("code").Unique(),
		index.Fields("parent_id"),
	}
}

// Annotations 自定义表名
func (Menus) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_menus"},
	}
}
