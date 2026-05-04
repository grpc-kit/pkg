package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Services holds the schema definition for the Services entity.
type Services struct {
	ent.Schema
}

// Fields of the table.
func (Services) Fields() []ent.Field {
	return []ent.Field{
		field.String("code").
			MaxLen(64).
			NotEmpty().
			Comment("服务短代码，如 admin.v1.oneops"),
		field.String("grpc_name").
			MaxLen(256).
			NotEmpty().
			Comment("gRPC 全限定服务名"),
		field.String("display_name").
			Default("").
			Comment("服务展示名称"),
		field.String("description").
			Default("").
			Comment("详细描述"),
		field.Bool("protected").
			Default(false).
			Comment("是否系统保护服务"),
	}
}

// Mixin of the table.
func (Services) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (Services) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("code").Unique(),
		index.Fields("grpc_name").Unique(),
	}
}

// Annotations 自定义表名
func (Services) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_services"},
	}
}
