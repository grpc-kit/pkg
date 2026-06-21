package schema

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"
	"time"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/mixin"
)

// Code 字段规范常量
const (
	// CodeMinLen code 最小长度
	CodeMinLen = 2
	// CodeMaxLen code 最大长度
	CodeMaxLen = 32
	// CodeAutoLen 自动生成 code 的固定长度（通用，适用于 roles/departments/groups 等）
	CodeAutoLen = 12
	// MenuCodeAutoLen 菜单专用自动生成 code 的随机部分长度
	// 菜单 code 通常带父级前缀（如 admin.），6 位随机码足以保证唯一性
	MenuCodeAutoLen = 6
)

// codeAlphabet 自动生成 code 使用的字符集（移除易混淆字符 i/l/o/0/1）
const codeAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

// codeLetters 仅小写字母（移除易混淆字符 i/l/o），用于生成 code 首字符
const codeLetters = "abcdefghjkmnpqrstuvwxyz"

// codeRegexp 合法 code 基础正则：
// 以小写字母开头，中间允许小写字母/数字/连字符/点号/冒号，以字母或数字结尾。
// 连续分隔符（如 "--"、".."、"::"、"-."、".:"）的检查在 ValidateCode 中单独处理。
var codeRegexp = regexp.MustCompile(`^[a-z][a-z0-9.:-]*[a-z0-9]$`)

// GenerateCodeWithLen 生成指定长度的随机 code
// 格式: [a-z] 开头 + (length-1) 位 [a-z0-9]，使用 crypto/rand 确保加密安全
// 生成字符集移除了易混淆字符 i/l/o/0/1
func GenerateCodeWithLen(length int) (string, error) {
	if length < 2 {
		return "", fmt.Errorf("generate code: length %d is below minimum 2", length)
	}

	buf := make([]byte, length)
	randBytes := make([]byte, length)

	if _, err := rand.Read(randBytes); err != nil {
		return "", fmt.Errorf("generate code: crypto/rand read failed: %w", err)
	}

	// 首字符限定小写字母（23 个字母），确保 code 以字母开头
	buf[0] = codeLetters[int(randBytes[0])%len(codeLetters)]

	// 后续字符使用去除易混淆字符后的字母数字集（31 个字符）
	for i := 1; i < length; i++ {
		buf[i] = codeAlphabet[int(randBytes[i])%len(codeAlphabet)]
	}

	return string(buf), nil
}

// GenerateCode 自动生成一个 12 位的随机 code（通用，适用于 roles/departments/groups 等）
// 总组合数: 23 × 31^11 ≈ 1.79 × 10^17，碰撞概率极低
func GenerateCode() (string, error) {
	return GenerateCodeWithLen(CodeAutoLen)
}

// GenerateMenuCode 生成菜单专用 code
// 当 parentCode 非空时，返回 "parentCode." + 6 位随机码（如 "admin.abc123"）
// 当 parentCode 为空时，返回 6 位随机码（顶级菜单）
// 如果拼接后总长度超过 CodeMaxLen(32)，则截断随机部分以适配
func GenerateMenuCode(parentCode string) (string, error) {
	randomPart, err := GenerateCodeWithLen(MenuCodeAutoLen)
	if err != nil {
		return "", err
	}

	if parentCode == "" {
		return randomPart, nil
	}

	// parentCode + "." + randomPart
	result := parentCode + "." + randomPart

	// 如果总长度超过 CodeMaxLen，截断随机部分
	if len(result) > CodeMaxLen {
		// 保留 parentCode + "." + 尽可能多的随机字符，但至少保留 2 位随机字符
		maxRandom := CodeMaxLen - len(parentCode) - 1 // -1 for "."
		if maxRandom < 2 {
			return "", fmt.Errorf("generate menu code: parent code %q too long, cannot fit random suffix within CodeMaxLen(%d)", parentCode, CodeMaxLen)
		}
		result = parentCode + "." + randomPart[:maxRandom]
	}

	return result, nil
}

// ValidateCode 校验 code 是否符合规范
// 规则：
//   - 长度：2-32 字符
//   - 以小写字母 [a-z] 开头
//   - 中间允许 [a-z0-9.:-]，不允许连续分隔符（"--"、".."、"::"、"-."、".-"、".:"、":."、":-"、"-:"）
//   - 以字母或数字 [a-z0-9] 结尾
//   - 不允许大写字母、下划线、空格等特殊字符
func ValidateCode(code string) error {
	n := len(code)
	if n < CodeMinLen {
		return fmt.Errorf("code length %d is below minimum %d", n, CodeMinLen)
	}
	if n > CodeMaxLen {
		return fmt.Errorf("code length %d exceeds maximum %d", n, CodeMaxLen)
	}
	if !codeRegexp.MatchString(code) {
		return fmt.Errorf("code %q is invalid: must start with [a-z], contain only [a-z0-9.:-], end with [a-z0-9]", code)
	}
	for i := 1; i < len(code); i++ {
		if isCodeSeparator(code[i-1]) && isCodeSeparator(code[i]) {
			return fmt.Errorf("code %q is invalid: consecutive separators are not allowed", code)
		}
	}
	return nil
}

func isCodeSeparator(ch byte) bool {
	return ch == '-' || ch == '.' || ch == ':'
}

// ReservedMenuCodes 是系统保留的菜单 code，不允许用户通过 CreateMenu 创建。
// 这些 code 对应内置的根菜单和端入口菜单，由 builtinMenuSeeds() 初始化。
var ReservedMenuCodes = map[string]bool{
	"root":    true,
	"admin":   true,
	"portal":  true,
	"miniapp": true,
	"mobile":  true,
}

// IsReservedCode 检查给定 code 是否为系统保留码。
func IsReservedCode(code string) bool {
	return ReservedMenuCodes[code]
}

// EnsureCode 确保 code 有值：如果传入的 code 为空则自动生成，否则校验合法性。
// 不会检查保留码——保留码检查由调用方在合适的时机执行（如 CreateMenu）。
// 适用于 Create 接口中客户端可选提供 code 的场景。
func EnsureCode(code string) (string, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return GenerateCode()
	}
	if err := ValidateCode(code); err != nil {
		return "", err
	}
	return code, nil
}

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

// AuditMixin 创建或更新人员属性
type AuditMixin struct {
	mixin.Schema
}

// Fields xx
func (AuditMixin) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("created_by").
			Optional().
			Default(0),
		field.Int64("updated_by").
			Optional().
			Default(0),
	}
}

// FieldNameNormalize 移除字段名末尾的 "_encrypted", "_hash" 使其与 proto 等定义一致
func FieldNameNormalize(name string) string {
	return strings.ReplaceAll(name, "_encrypted", "")
}
