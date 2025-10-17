package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
)

// Credentials holds the schema definition for the Credentials entity.
type Credentials struct {
	ent.Schema
}

// Fields of the table.
func (Credentials) Fields() []ent.Field {
	return []ent.Field{
		// 基本信息
		field.String("name").
			Comment("凭证显示名称"),
		
		// 凭证分类字段 (原 proto enum 转为 int)
		field.Int("credential_type").
			Default(0).
			Comment("凭证类型: 0=未指定, 1=API_KEY, 2=SYMMETRIC_KEY, 3=KEY_PAIR, 4=X509, 5=LICENSE, 6=JWKS, 7=HSM_REF, 8=FIDO, 99=OTHER"),
		field.Int("credential_algorithm").
			Default(0).
			Comment("算法类型: 0=未指定, 1=RSA, 2=ECDSA, 3=ED25519, 4=HMAC, 5=AES, 6=CHACHA20_POLY1305, 99=OTHER"),
		field.Int("credential_usage").
			Default(0).
			Comment("凭证用途: 0=未指定, 1=SIGNING, 2=ENCRYPTION, 10=AUTH, 11=LICENSE, 12=OTP"),
		field.Int("credential_visibility").
			Default(1).
			Comment("可见性: 0=未指定, 1=PRIVATE, 2=INTERNAL, 3=PUBLIC, 4=GROUP"),
		field.Int("credential_status").
			Default(1).
			Comment("状态: 0=未指定, 1=ACTIVE, 2=PENDING, 3=DISABLED, 4=EXPIRED, 5=REVOKED"),
		field.Int("credential_source").
			Default(0).
			Comment("来源: 0=未指定, 1=SYSTEM, 2=USER, 3=KMS, 4=EXTERNAL"),
		
		// 外部引用
		field.String("key_id").
			Optional().
			Comment("外部系统 Key ID / JWKS ID / HSM ID"),
		
		// API Key 相关字段
		field.String("api_key").
			Optional().
			Comment("API Key 的公有标识"),
		field.Bytes("api_secret_encrypted").
			Optional().
			Sensitive().
			Comment("API Secret / 私密部分，敏感数据"),
		
		// 密钥对相关字段
		field.String("public_key").
			Optional().
			Comment("公钥内容（PEM/DER 格式）"),
		field.Bytes("private_key_encrypted").
			Optional().
			Sensitive().
			Comment("私钥内容（PEM/DER 格式），敏感数据"),
		field.Bytes("passphrase_encrypted").
			Optional().
			Sensitive().
			Comment("私钥加密口令，可选"),
		
		// X.509 证书相关字段
		field.Bytes("certificate").
			Optional().
			Comment("主证书（PEM/DER 格式）"),
		field.JSON("ca_chain", [][]byte{}).
			Optional().
			Comment("可选 CA 证书链（顺序从根到中间证书）"),
		
		// 许可证相关字段
		field.String("license_key_encrypted").
			Optional().
			Comment("许可证密钥或主体内容"),
		field.String("signature").
			Optional().
			Comment("许可证数字签名，用于验证完整性"),

		// 对称密钥和 JWKS
		field.Bytes("symmetric_key").
			Optional().
			Sensitive().
			Comment("对称密钥 / HMAC / JWT"),
		field.String("jwks_uri").
			Optional().
			Comment("JWKS URI"),
		
		// 时间相关字段
		field.Time("not_before").
			Optional().
			Nillable().
			Comment("生效时间（Not Before）"),
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("过期时间"),
		
		// 附加元数据
		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("自定义业务属性，许可证附加信息，如授权范围、用户数、有效期等"),
		field.String("description").
			Optional().
			Comment("凭证说明或备注"),
	}
}

// Edges of the table.
func (Credentials) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (Credentials) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixinWithoutDeleted{},
		AuditMixin{},
	}
}

// Annotations 自定义表名
func (Credentials) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_credentials"},
	}
}
