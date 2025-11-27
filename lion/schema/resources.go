package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
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
		field.String("display_name").
			Default("").
			Comment("友好展示名称"),
		// field.String("i18n_key").
		//	Optional().
		//	Comment("国际化键值，用于前端多语言显示的标识符"),

		field.Int("sort_order").
			Default(100).
			Comment("资源排序顺序，用于同级资源的显示顺序，数值越小排序越靠前，建议使用 10 的倍数便于后续插入，默认值：100，范围：1-9999"),
		field.Int("resource_type").
			Default(0).
			Comment("用途类型，对应 api/known/admin/v1/common.proto 中定义"),

		field.Int("resource_scope").
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
		// 一个 Resource 可以对应多个 RoleResources (中间实体)
		edge.To("lion_permissions", Permissions.Type).Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Mixin of the table.
func (Resources) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
		AuditMixin{},
	}
}

// Indexes 定义索引
func (Resources) Indexes() []ent.Index {
	return []ent.Index{
		// 父资源ID索引，用于快速查找子资源
		index.Fields("parent_id"),
		// 类型和作用域组合索引，用于按类型和作用域查询
		index.Fields("resource_type", "resource_scope"),
		// 启用状态索引，用于快速过滤启用的资源
		index.Fields("enabled"),
		// 排序顺序索引，用于排序查询
		index.Fields("sort_order"),
		// 路径索引，用于路由匹配
		index.Fields("path"),
		// 父资源ID + 排序顺序组合索引，用于同级资源排序
		index.Fields("parent_id", "sort_order"),
	}
}

// Annotations 自定义表名
func (Resources) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_resources"},
	}
}
