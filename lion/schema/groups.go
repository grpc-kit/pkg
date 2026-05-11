package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Groups 存储用户组信息，实现 RBAC 权限管理
type Groups struct {
	ent.Schema
}

// Fields of the table.
func (Groups) Fields() []ent.Field {
	return []ent.Field{
		field.String("code").
			Unique().
			MaxLen(128).
			NotEmpty().
			Comment("用户组名"),
		field.String("display_name").
			MaxLen(256).
			NotEmpty().
			Comment("部门名称，用于系统内部显示和业务逻辑"),
		// field.String("i18n_key").
		//	Optional().
		//	Comment("国际化键值，用于前端多语言显示的标识符"),
		field.Int("group_type").
			Default(0).
			Comment("群组类型，对应 api/known/admin/v1/common.proto 中定义"),
		field.Int("group_status").
			Default(0).
			Comment("群组状态，对应 api/known/admin/v1/common.proto 中定义"),

		field.Int("sort_order").
			Default(100).
			Comment("群组排序顺序，用于同级群组的显示顺序，数值越小排序越靠前，建议使用 10 的倍数便于后续插入，默认值：100，范围：1-9999"),
		field.Int("parent_id").
			Default(0).
			Comment("父群组ID，为0表示顶级群组"),
		field.Int("max_members").
			Default(0).
			Comment("群组最大成员数量限制，0表示不限制"),
		field.JSON("metadata", map[string]string{}).
			Default(map[string]string{}).
			Comment("元数据，用于存储自定义属性，对应 proto 中的 map<string, string> metadata"),
		field.Int("ref_id").
			Default(0).
			Comment("类型关联引用ID：DEPARTMENT→部门ID，ROLE→角色ID；其他类型为0"),
		field.String("ref_expr").
			Default("").
			MaxLen(4096).
			Comment("类型关联表达式：DYNAMIC→成员过滤规则，EXTERNAL→外部源描述(JSON)；其他类型为空"),

		field.Int("visibility").
			Default(0).
			Comment("可见性定义，对应 api/known/admin/v1/common.proto 中定义"),

		field.String("description").
			Default("").
			Comment("用户组描述"),
	}
}

// Edges of the table.
func (Groups) Edges() []ent.Edge {
	return []ent.Edge{
		// 一个 Role 可以对应多个 RoleMenu (中间实体)
		edge.To("lion_groups", GroupRoles.Type),
		/*
			edge.From("lion_departments", Departments.Type).
				Ref("lion_groups").
				Field("department_id").
				Unique(),
		*/
	}
}

// Mixin of the table.
func (Groups) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{}, // 支持软删除，包含 deleted_at 字段
		AuditMixin{},
	}
}

// Indexes 定义索引
func (Groups) Indexes() []ent.Index {
	return []ent.Index{
		// 群组名称唯一索引（已在字段定义中设置 Unique，这里作为补充）
		index.Fields("code").Unique(),
		// 群组类型索引，用于按类型过滤查询
		index.Fields("group_type"),
		// 群组状态索引，用于按状态过滤查询
		index.Fields("group_status"),
		// 类型+引用ID组合索引，支持按类型+关联ID查询（如查找关联某角色/部门的群组）
		index.Fields("group_type", "ref_id"),
	}
}

// Annotations 自定义表名
func (Groups) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_groups"},
	}
}
