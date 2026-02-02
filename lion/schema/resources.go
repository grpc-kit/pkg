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
		field.Int64("parent_id").
			Default(0).
			Comment("父资源 ID，为 0 表示顶级资源"),
		field.String("code").
			MaxLen(128).
			NotEmpty().
			Comment("资源名称"),
		field.String("display_name").
			Default("").
			Comment("友好展示名称"),
		field.Int("resource_type").
			Default(0).
			Comment("用途类型，对应 api/known/admin/v1/common.proto 中定义"),
		field.Int("resource_status").
			Default(0).
			Comment("是否启用该资源项，禁用后完全不可访问"),
		field.Int("visibility").
			Default(0).
			Comment("可见性定义，对应 api/known/admin/v1/common.proto 中定义"),
		field.Int("sort_order").
			Default(100).
			Comment("资源排序顺序，用于同级资源的显示顺序，数值越小排序越靠前，建议使用 10 的倍数便于后续插入，默认值：100，范围：1-9999"),
		/*
			field.Int("resource_scope").
				Default(0).
				Comment("作用范围，对应 api/known/admin/v1/common.proto 中定义"),
		*/
		/*
			field.Bool("hidden").
				Default(false).
				Comment("是否在资源列表中隐藏该节点"),
			field.Bool("hide_children").
				Default(false).
				Comment("是否隐藏该资源节点的子项"),
		*/
		field.String("locator").
			MaxLen(512).
			Default("").
			Comment("资源路径"),
		field.String("visual").
			MaxLen(256).
			Default("").
			Comment("图标名称，如 UserOutlined"),
		field.String("manifest").
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
		edge.To("lion_resource_scopes", ResourceScopes.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
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
		// 排序顺序索引，用于排序查询
		index.Fields("sort_order"),
	}
}

// Annotations 自定义表名
func (Resources) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_resources"},
	}
}
