package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// Credentials 企业级通用凭证实体，支持 API Key、X.509 证书、非对称密钥对、
// HMAC/对称密钥、软件许可证等多种凭证类型
// 对应 proto: Credential (admin.common.proto)
// 表名: lion_credentials
type Credentials struct {
	ent.Schema
}

// Fields of the table.
func (Credentials) Fields() []ent.Field {
	return []ent.Field{
		// === 标识区（proto field 1-2）===
		field.String("code").
			Unique().
			MaxLen(32).
			Comment("凭证唯一编码，创建后不可修改（2-32字符，小写字母开头）"),

		// === 展示区（proto field 3-4）===
		field.String("display_name").
			Default("").
			MaxLen(256).
			Comment("前端展示名称，用于凭证列表、详情页等用户可见场景"),
		field.String("description").
			Optional().
			Comment("凭证说明或备注"),

		// === 分类区（proto field 5-7，原 proto enum 转为 int）===
		field.Int("credential_type").
			Default(0).
			Comment("凭证类型: 0=未指定, 1=API_KEY, 2=SYMMETRIC_KEY, 3=KEY_PAIR, 4=X509, 5=LICENSE, 6=SECRET"),
		field.Int("credential_algorithm").
			Default(0).
			Comment("算法类型: 0=未指定, 1=RSA, 2=ECDSA, 3=ED25519, 4=HMAC, 5=AES, 6=CHACHA20_POLY1305, 10=SM2, 11=SM4, 12=SM9, 99=CUSTOM"),
		field.Int("credential_usage").
			Default(0).
			Comment("凭证用途: 0=未指定, 1=SIGNING, 2=ENCRYPTION, 10=AUTH, 11=OTP, 12=JWKS"),
		field.Int("credential_visibility").
			Default(1).
			Comment("可见性: 0=未指定, 1=GLOBAL, 2=SUBTREE, 3=LOCAL, 4=RESTRICTED, 5=SPECIFIC"),
		field.Int("credential_status").
			Default(1).
			Comment("状态: 0=未指定, 1=ACTIVE, 2=PENDING, 3=DISABLED, 4=EXPIRED, 5=REVOKED"),
		field.Int("credential_source").
			Default(0).
			Comment("来源: 0=未指定, 1=SYSTEM, 2=USER, 3=KMS, 4=EXTERNAL"),

		// === 管理区（proto field 8-11）===
		field.Bool("protected").
			Default(false).
			Comment("是否受保护（受保护记录不可删除，如内置签名密钥）"),

		// === 密钥材料区（proto field 12-18）===
		// 密钥指纹
		field.String("fingerprint").
			Optional().
			Comment("密钥指纹（SHA-256 摘要，64 字符 hex），用于幂等去重。生成策略因类型而异：API_KEY=api_key SHA-256, SYMMETRIC_KEY=密钥 SHA-256, KEY_PAIR=公钥 SHA-256, X509=证书 SHA-256, LICENSE=license_key SHA-256, SECRET=密文 SHA-256"),

		// === key_material: API Key（proto oneof 12）===
		field.String("api_key").
			Optional().
			Comment("API Key 的公有标识"),
		field.Bytes("api_secret_encrypted").
			Optional().
			Sensitive().
			Comment("API Secret / 私密部分，敏感数据"),

		// === key_material: KeyPair（proto oneof 13）===
		// 注意: private_key_encrypted 同时复用于 X509 类型（proto oneof 15），
		// 因 oneof key_material 保证互斥，一条记录不会同时有两种类型的私钥
		field.Bytes("public_key").
			Optional().
			Comment("公钥内容（PEM/DER 格式）"),
		field.Bytes("private_key_encrypted").
			Optional().
			Sensitive().
			Comment("私钥内容（PEM/DER 格式），敏感数据；KEY_PAIR 类型为密钥对私钥，X509 类型为证书对应私钥"),
		field.Bytes("passphrase_encrypted").
			Optional().
			Sensitive().
			Comment("私钥加密口令，可选；同时服务于 KEY_PAIR 和 X509 类型"),

		// === key_material: X509（proto oneof 14）===
		// private_key_encrypted 复用 KeyPair 组中定义的字段，此处不重复定义
		field.Bytes("certificate").
			Optional().
			Comment("主证书（PEM/DER 格式）"),
		field.JSON("ca_chain", [][]byte{}).
			Optional().
			Comment("可选 CA 证书链（顺序从根到中间证书）"),

		// === key_material: License（proto oneof 15）===
		field.Bytes("license_key_encrypted").
			Optional().
			Sensitive().
			Comment("许可证密钥或主体内容，敏感数据"),
		field.Bytes("signature").
			Optional().
			Comment("许可证数字签名，用于验证完整性"),

		// === key_material: Symmetric（proto oneof 16）===
		field.Bytes("symmetric_key_encrypted").
			Optional().
			Sensitive().
			Comment("对称密钥 / HMAC / JWT / AES-GCM 加密后的完整 Token（可解密还原）；SECRET 类型复用此字段存储非密钥类密文"),

		// === 生命周期区（proto field 18-19）===
		field.Time("not_before").
			Optional().
			Nillable().
			Comment("生效时间（Not Before）"),
		field.Time("expires_at").
			Optional().
			Nillable().
			Comment("过期时间"),

		// === 扩展区（proto field 20）===
		field.JSON("metadata", map[string]string{}).
			Optional().
			Comment("自定义业务属性，许可证附加信息，如授权范围、用户数、有效期等"),
	}
}

// Edges of the table.
func (Credentials) Edges() []ent.Edge {
	return nil
}

// Mixin of the table.
func (Credentials) Mixin() []ent.Mixin {
	return []ent.Mixin{
		TimeMixin{},  // created_at, updated_at, deleted_at（支持软删除）
		AuditMixin{}, // created_by, updated_by
	}
}

// Indexes 定义索引
func (Credentials) Indexes() []ent.Index {
	return []ent.Index{
		// code 唯一索引已在字段定义中设置 Unique()
		// fingerprint 条件唯一索引：仅非空值唯一（token 场景存 SHA-256 摘要需幂等去重；
		// License 等类型可能不设 fingerprint，多条 NULL 不冲突）
		index.Fields("fingerprint").Unique().Annotations(
			entsql.IndexWhere("fingerprint IS NOT NULL AND fingerprint != ''"),
		),
		// 按类型过滤（管理后台分类展示）
		index.Fields("credential_type"),
		// 按状态过滤（常用：只查 ACTIVE）
		index.Fields("credential_status"),
		// 按用途过滤
		index.Fields("credential_usage"),
		// 按来源过滤
		index.Fields("credential_source"),
		// 过期时间扫描（定时清理任务）
		index.Fields("expires_at"),
		// 按创建者查询（token 管理按用户筛选）
		index.Fields("created_by"),
	}
}

// Annotations 自定义表名
func (Credentials) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "lion_credentials"},
	}
}
