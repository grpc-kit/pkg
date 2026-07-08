// Package auth — GRN (Generic Resource Name) 实现
//
// GRN 借鉴 AWS ARN 的 6 段固定结构：
//
//	grn:<partition>:<service>:<region>:<account-id>:<resource-type>/<resource-path>
//
// 完整规范见仓库内文档 adm/docs/spec/grn.md。本文件提供 Go 侧的解析 / 字符串化 /
// 通配匹配实现，与 Rego 端 `grn_match` 函数 MUST 行为一致；两侧共享同一份
// table-driven 测试用例（pkg/auth/testdata/grn_match.json）。
//
// 设计要点：
//   - 6 段强校验：scheme MUST 为 "grn"；段数 MUST 等于 6，否则视为非法 GRN。
//   - 第 6 段（resource）内部可能包含 ":"（备选形态 type:id），因此 Parse MUST
//     使用 SplitN(s, ":", 6) 而非 Split。
//   - partition 段 MUST 严格相等：不接受 "*" / "" 通配（spec/grn.md R-PART-2）。
//   - service / region / account 段 MAY 在 pattern 端为 "*"（或 ""=空 → 视为通配）。
//   - resource 段含 "*" 时走 glob.match(pattern, ["/"], want) 语义。
package auth

import (
	"errors"
	"fmt"
	"strings"
)

// DefaultPartition 是 GRN partition 段在 Config.Partition 为空时使用的默认值。
const DefaultPartition = "grpc-kit"

// 已登记的 GRN partition 枚举；新增 partition MUST 同步更新 adm/docs/spec/grn.md §6。
const (
	PartitionDefault = "grpc-kit"     // 默认分区
	PartitionCN      = "grpc-kit-cn"  // 中国大陆合规分区（预留）
	PartitionGov     = "grpc-kit-gov" // 政企专网分区（预留）
)

// grnScheme 是 GRN 的固定 scheme 字面量。
const grnScheme = "grn"

// grnSegmentCount 是 GRN 固定段数（含 scheme），MUST 与 spec/grn.md §4.1 一致。
const grnSegmentCount = 6

// ErrInvalidGRN 表示输入字符串不符合 GRN 6 段结构。
var ErrInvalidGRN = errors.New("auth: invalid GRN")

// GRN 表示一个解析后的 GRN（6 段）。
//
// 字段顺序与 spec/grn.md §2 的段位顺序严格一致：
//
//	grn:<Partition>:<Service>:<Region>:<Account>:<Resource>
//
// Resource 段保留完整字符串（含 type/path 或 type:id 形态），具体子结构由调用方解析。
type GRN struct {
	Partition string
	Service   string
	Region    string
	Account   string
	Resource  string
}

// Parse 解析一个 GRN 字符串；不合法时返回 ErrInvalidGRN 的包装错误。
//
// 注意：第 6 段可能包含 ":"（例如 `type:id` 形态），因此使用 SplitN 切分。
func Parse(s string) (*GRN, error) {
	if s == "" {
		return nil, fmt.Errorf("%w: empty string", ErrInvalidGRN)
	}

	parts := strings.SplitN(s, ":", grnSegmentCount)
	if len(parts) != grnSegmentCount {
		return nil, fmt.Errorf("%w: expected %d segments, got %d: %q", ErrInvalidGRN, grnSegmentCount, len(parts), s)
	}
	if parts[0] != grnScheme {
		return nil, fmt.Errorf("%w: scheme must be %q, got %q", ErrInvalidGRN, grnScheme, parts[0])
	}
	if parts[1] == "" {
		return nil, fmt.Errorf("%w: partition must not be empty", ErrInvalidGRN)
	}

	return &GRN{
		Partition: parts[1],
		Service:   parts[2],
		Region:    parts[3],
		Account:   parts[4],
		Resource:  parts[5],
	}, nil
}

// String 将 GRN 序列化回字符串形态（6 段）。
func (g *GRN) String() string {
	if g == nil {
		return ""
	}
	return strings.Join([]string{grnScheme, g.Partition, g.Service, g.Region, g.Account, g.Resource}, ":")
}

// Match 判定 pattern 是否覆盖 want。语义与 Rego 端 `grn_match` 完全一致：
//
//   - 两端 MUST 均为合法 6 段 GRN，scheme 严格为 "grn"。
//   - partition 段 MUST 严格相等：pattern 端 "*" / "" 均**不接受**作为通配。
//   - service / region / account：pattern 端 "*" 或空字符串视为通配；否则严格相等。
//   - resource：pattern 含 "*" 时走 glob 匹配（分隔符 "/"，与 OPA glob.match 一致），
//     不含 "*" 时严格相等。
//
// want 端 MUST 是具体值（解析自请求上下文）；在 want 端使用通配是调用方的逻辑错误，
// 本函数不为此做特殊处理（按字面量比较）。
func Match(pattern, want string) bool {
	p, errP := Parse(pattern)
	w, errW := Parse(want)
	if errP != nil || errW != nil {
		return false
	}

	// partition: 严格相等，不允许通配（R-PART-2 / R-PART-4）
	if p.Partition != w.Partition {
		return false
	}
	if !wildcardOrEqual(p.Service, w.Service) {
		return false
	}
	if !wildcardOrEqual(p.Region, w.Region) {
		return false
	}
	if !wildcardOrEqual(p.Account, w.Account) {
		return false
	}
	return resourceSegmentMatch(p.Resource, w.Resource)
}

// wildcardOrEqual 用于 service / region / account 三段：
// pattern 端 "*" 或空字符串均视为通配；否则要求严格相等。
func wildcardOrEqual(pattern, want string) bool {
	if pattern == "*" || pattern == "" {
		return true
	}
	return pattern == want
}

// resourceSegmentMatch 用于第 6 段（resource）：
//   - "*" 表示任意；
//   - 不含 "*" 时严格相等；
//   - 含 "*" 时使用 glob 匹配（分隔符 "/"）。
//
// 该实现 MUST 与 Rego 端 `glob.match(pattern, ["/"], want)` 行为一致。
func resourceSegmentMatch(pattern, want string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == want
	}
	return globMatch(pattern, want, '/')
}

// globMatch 实现 OPA `glob.match(pattern, ["/"], want)` 语义的最小子集：
//
//   - "*"  匹配任意非分隔符序列（含空串），不跨越 sep
//   - "**" 匹配任意序列（含空串），可跨越 sep
//   - "?"  匹配单个非分隔符字符
//   - 其余字符严格相等比较
//
// 不支持字符类 `[abc]` / 转义 `\*` —— 这两种语法不在 GRN 资源段的合法表达范围内
// （详见 spec/grn.md §4.2 中关于 resource segment 的约束）。
//
// 实现采用递归回溯，pattern / want 通常很短（< 200 字节），性能足够。
func globMatch(pattern, want string, sep byte) bool {
	// 先把 "**" 这种"任意序列"的语义剥离掉，再走单 "*" 的快速路径。
	return globMatchBytes([]byte(pattern), []byte(want), sep)
}

func globMatchBytes(pat, s []byte, sep byte) bool {
	for len(pat) > 0 {
		switch pat[0] {
		case '*':
			// "**" => 任意序列（可跨 sep）
			if len(pat) > 1 && pat[1] == '*' {
				rest := pat[2:]
				if len(rest) == 0 {
					return true
				}
				// 尝试在 s 的每一个起点匹配 rest
				for i := 0; i <= len(s); i++ {
					if globMatchBytes(rest, s[i:], sep) {
						return true
					}
				}
				return false
			}
			// 单 "*" => 任意非 sep 序列（含空）
			rest := pat[1:]
			for i := 0; i <= len(s); i++ {
				if globMatchBytes(rest, s[i:], sep) {
					return true
				}
				if i < len(s) && s[i] == sep {
					// 单 "*" 不能跨越 sep；只能尝试到 sep 之前
					break
				}
			}
			return false
		case '?':
			if len(s) == 0 || s[0] == sep {
				return false
			}
			pat = pat[1:]
			s = s[1:]
		default:
			if len(s) == 0 || s[0] != pat[0] {
				return false
			}
			pat = pat[1:]
			s = s[1:]
		}
	}
	return len(s) == 0
}

// NormalizePartition 在 cfg 为空时返回默认 partition。
//
// 该函数供 input_builder / static_dict 在替换 ${partition} 占位符时使用，
// 确保 Config.Partition 未显式设置时仍能产生合法 GRN。
func NormalizePartition(p string) string {
	if p == "" {
		return DefaultPartition
	}
	return p
}
