package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
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
			Comment("父部门ID，构建树形组织结构，值为 0 表示顶级部门"),
		field.String("code").
			MaxLen(256).
			NotEmpty().
			Comment("部门代号，用于系统内部显示和业务逻辑"),
		field.String("display_name").
			MaxLen(256).
			NotEmpty().
			Comment("部门名称，用于系统内部显示和业务逻辑"),
		// field.String("i18n_key").
		//	Optional().
		//	Comment("国际化键值，用于前端多语言显示的标识符"),
		field.Int("department_type").
			Default(0).
			Comment("部门类型分类：0-未指定，1-业务部门，2-支持部门，3-管理部门，4-虚拟部门"),
		field.Int("department_status").
			Default(1).
			Comment("部门运营状态：0-未指定，1-正常运营，2-暂停运营，3-已解散，4-合并中"),
		field.Int("sort_order").
			Default(100).
			Comment("部门排序顺序，用于同级部门的显示顺序，数值越小排序越靠前，建议使用 10 的倍数便于后续插入，默认值：100，范围：1-9999"),
		field.Bytes("email_encrypted").
			Sensitive().
			Optional().
			Comment("部门公共邮箱地址，加密存储"),
		field.Bytes("phone_number_encrypted").
			Sensitive().
			Optional().
			Comment("部门联系电话，加密存储"),
		field.Bytes("address_encrypted").
			Sensitive().
			Optional().
			Comment("部门办公地址，加密存储"),
		field.String("cost_center_code").
			Sensitive().
			Optional().
			Comment("成本中心编码，用于财务核算和成本控制"),
		field.String("budget_item_code").
			Sensitive().
			Optional().
			Comment("预算编码，用于预算管理和费用控制"),
		field.Int("max_members").
			Default(0).
			Comment("部门最大成员数限制，值为 0 表示无限制"),
		field.String("external_id").
			Optional().
			Comment("外部系统标识符，用于第三方系统集成"),
		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("扩展元数据，存储自定义业务属性"),
		field.String("description").
			Default("").
			Comment("部门描述信息，详细说明部门职责和业务范围"),
	}
}

// Edges of the table.
func (Departments) Edges() []ent.Edge {
	return []ent.Edge{
		// 一个 Menu 可以对应多个 RoleMenu (中间实体)
		// edge.To("lion_users", Users.Type),
		edge.To("lion_role_departments", RoleDepartments.Type),
		edge.To("lion_user_departments", UserDepartments.Type),
		edge.To("lion_groups", Groups.Type),
	}
}

// Mixin of the table.
func (Departments) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
		AuditMixin{},
	}
}

// Annotations 自定义表名
func (Departments) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_departments"},
	}
}
