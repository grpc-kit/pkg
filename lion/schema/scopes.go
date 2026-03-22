package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
)

// Scopes 系统作用域（表 lion_scopes）。
// 内置数据由 pkg/admin CreateDatabaseInitialize 幂等写入：PLATFORM(1) 为 admin、user、app；ACTION(2) 为 create、update、delete、readonly。
type Scopes struct {
	ent.Schema
}

// Fields of the table.
func (Scopes) Fields() []ent.Field {
	return []ent.Field{
		field.String("code").
			Unique().
			MaxLen(128).
			NotEmpty().
			Comment("名称"),
		field.Int("scope_type").
			Default(0).
			Comment("用途类型，对应 api/known/admin/v1/common.proto 中定义"),
		field.String("display_name").
			Default("").
			Comment("友好展示名称"),
		field.Bool("protected").
			Default(false).
			Comment("是否为保护资源，保护资源不能被删除，描述等可更改"),
		field.String("description").
			Default("").
			Comment("详细描述"),
	}
}

// Edges of the table.
func (Scopes) Edges() []ent.Edge {
	return []ent.Edge{
		edge.To("lion_resource_scopes", ResourceScopes.Type).
			Annotations(entsql.OnDelete(entsql.Cascade)),
	}
}

// Mixin of the table.
func (Scopes) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},
	}
}

// Annotations 自定义表名
func (Scopes) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_scopes"},
	}
}
