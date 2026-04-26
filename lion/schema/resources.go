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
		field.Int("resource_type_id").
			Positive().
			Comment("关联 lion_resource_types 表 ID"),
		field.String("resource_type_code").
			MaxLen(64).
			NotEmpty().
			Comment("资源类型代码，冗余自 lion_resource_types.code"),
		field.String("service_code").
			MaxLen(64).
			NotEmpty().
			Comment("服务短代码，对应 lion_services.code"),
		field.String("tenant_id").
			MaxLen(64).
			Default("").
			Comment("租户 ID，单租户场景可为空"),
		field.String("region").
			MaxLen(32).
			Default("").
			Comment("区域代码，单区域场景可为空"),
		field.String("resource_path").
			MaxLen(255).
			NotEmpty().
			Comment("资源路径，支持 * 通配"),
		field.String("grn").
			MaxLen(512).
			Default("").
			Comment("资源 GRN，迁移阶段由应用层或迁移脚本维护"),
		field.String("code").
			MaxLen(128).
			NotEmpty().
			Comment("资源名称"),
		field.String("name").
			MaxLen(512).
			Default("").
			Comment("兼容期保留的稳定资源名（旧 GRN 字段）"),
		field.String("display_name").
			Default("").
			Comment("友好展示名称"),
		field.Int("resource_type").
			Default(0).
			Comment("兼容期保留的旧资源类型枚举字段"),
		field.Int("resource_status").
			Default(0).
			Comment("兼容期保留的旧资源状态枚举字段"),
		field.String("resource_status_code").
			MaxLen(16).
			Default("active").
			Comment("新资源状态代码，如 active / disabled"),
		field.Int("visibility").
			Default(0).
			Comment("可见性定义，对应 api/known/admin/v1/common.proto 中定义"),
		field.Int("sort_order").
			Default(100).
			Comment("兼容期保留的资源排序顺序"),
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
			Comment("兼容期保留的资源路径字段"),
		field.String("visual").
			MaxLen(256).
			Default("").
			Comment("兼容期保留的图标字段"),
		field.String("manifest").
			Default("").
			Comment("兼容期保留的组件字段"),
		field.String("description").
			Default("").
			Comment("详细描述"),
		field.Bool("protected").
			Default(false).
			Comment("是否为保护资源，保护资源不能被删除，描述等可更改"),
	}
}

// Edges of the table.
func (Resources) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("lion_resource_types", ResourceTypes.Type).
			Ref("lion_resources").
			Field("resource_type_id").
			Unique().
			Required(),
		edge.To("lion_menus", Menus.Type),
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
		index.Fields("resource_type").Annotations(
			entsql.IndexWhere("parent_id = 0"),
		),
		index.Fields("resource_type_id", "tenant_id"),
		index.Fields("service_code", "resource_path"),
		index.Fields("sort_order"),
		index.Fields("code").Unique(),
		index.Fields("name").Unique().Annotations(
			entsql.IndexWhere("name <> ''"),
		),
		index.Fields("grn").Unique().Annotations(
			entsql.IndexWhere("grn <> ''"),
		),
	}
}

// Annotations 自定义表名
func (Resources) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_resources"},
	}
}
