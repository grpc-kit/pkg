package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Resources holds the schema definition for the Demo entity.
type Resources struct {
	ent.Schema
}

// Fields of the table.
func (Resources) Fields() []ent.Field {
	return []ent.Field{
		field.Int("parent_id").
			Default(0).
			Comment("父资源 ID，为 0 表示顶级资源"),
		field.String("name").
			MaxLen(128).
			NotEmpty().
			Comment("资源名称"),
		field.String("i18n_name").
			Default("").
			Comment("国际化标识"),
		field.Int("order_weight").
			Default(0).
			Comment("排序权重，越小越靠前"),
		field.Int("type").
			Default(0).
			Comment("用途类型，对应 api/known/admin/v1/common.proto 中定义"),
		field.Int("scope").
			Default(0).
			Comment("作用范围，对应 api/known/admin/v1/common.proto 中定义"),
		field.Bool("enabled").
			Default(true).
			Comment("是否启用该资源项，禁用后完全不可访问"),
		field.Bool("hidden").
			Default(false).
			Comment("是否在资源列表中隐藏该节点"),
		field.Bool("hide_children").
			Default(false).
			Comment("是否隐藏该资源节点的子项"),
		field.String("path").
			MaxLen(512).
			Default("").
			Comment("资源路径"),
		field.String("icon").
			MaxLen(256).
			Default("").
			Comment("图标名称，如 UserOutlined"),
		field.String("component").
			MaxLen(256).
			Default("").
			Comment("组件名称，如 UserOutlined"),
		field.String("description").
			Default("").
			Comment("详细描述"),
	}
}

// Edges of the table.
func (Resources) Edges() []ent.Edge {
	return []ent.Edge{
		// 一个 Menu 可以对应多个 RoleMenu (中间实体)
		edge.To("lion_role_resources", RoleResources.Type),
	}
}

// Mixin of the table.
func (Resources) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Annotations 自定义表名
func (Resources) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_resources"},
	}
}
