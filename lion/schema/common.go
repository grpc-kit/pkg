package schema

import (
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

// TimeMixin xx
type TimeMixin struct {
	mixin.Schema
}

// Fields xx
func (TimeMixin) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Immutable().
			Default(time.Now).
			Annotations(
				entsql.Default("CURRENT_TIMESTAMP"),
			),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Annotations(
				entsql.Default("CURRENT_TIMESTAMP"),
			),
		field.Time("deleted_at").
			Optional().
			Nillable(),
	}
}

// TimeMixinWithoutDeleted xx
type TimeMixinWithoutDeleted struct {
	mixin.Schema
}

// Fields xx
func (TimeMixinWithoutDeleted) Fields() []ent.Field {
	return []ent.Field{
		field.Time("created_at").
			Immutable().
			Default(time.Now).
			Annotations(
				entsql.Default("CURRENT_TIMESTAMP"),
			),
		field.Time("updated_at").
			Default(time.Now).
			UpdateDefault(time.Now).
			Annotations(
				entsql.Default("CURRENT_TIMESTAMP"),
			),
	}
}

// FieldNameNormalize 移除字段名末尾的 "_encrypted", "_hash" 使其与 proto 等定义一致
func FieldNameNormalize(name string) string {
	return strings.ReplaceAll(name, "_encrypted", "")
}
