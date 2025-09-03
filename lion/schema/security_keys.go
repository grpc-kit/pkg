package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// SecurityKeys holds the schema definition for the Demo entity.
type SecurityKeys struct {
	ent.Schema
}

// Fields of the table.
func (SecurityKeys) Fields() []ent.Field {
	return []ent.Field{
		field.String("public_key").
			NotEmpty().
			Comment("公钥 base64 编码存储"),
		field.Bytes("private_key_encrypted").
			Sensitive().
			NotEmpty().
			Comment("私钥对称加密存储"),
	}
}

// Edges of the table.
func (SecurityKeys) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (SecurityKeys) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
	}
}

// Annotations 自定义表名
func (SecurityKeys) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_security_keys"},
	}
}
