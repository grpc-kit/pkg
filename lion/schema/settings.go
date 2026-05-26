package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// GlobalSettings holds the schema definition for the GlobalSettings entity.
type GlobalSettings struct {
	ent.Schema
}

// Fields of the table.
func (GlobalSettings) Fields() []ent.Field {
	return []ent.Field{
		field.String("category").
			MaxLen(64).
			NotEmpty(),
		field.String("setting_key").
			MaxLen(128).
			NotEmpty(),
		field.Text("setting_value").
			Default(""),
		field.String("value_type").
			MaxLen(16).
			Default("string"),
		field.String("description").
			MaxLen(255).
			Default(""),
		field.Bool("protected").
			Default(false),
	}
}

// Mixin of the table.
func (GlobalSettings) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Indexes of the table.
func (GlobalSettings) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("category", "setting_key").Unique(),
		index.Fields("category"),
	}
}

// Annotations 自定义表名
func (GlobalSettings) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_settings"},
	}
}
