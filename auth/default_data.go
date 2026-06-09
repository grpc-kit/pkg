package auth

import "encoding/json"

// defaultData 返回最小兜底数据：一个 "superadmin" 角色 + 一个 ALLOW * 的策略。
//
// Phase 1 P10：替代旧版 defaultRBAC() 输出的 envoy RBAC YAML。
//
// 使用时机：DataProvider 与 Data 均为空（或返回空）时，作为框架启动的最后防线。
// 设计原则：
//   - 仅保留 `_builtin_superadmin` 一个全权策略，不再硬编码 admin/guest 区分；
//     精细化策略 MUST 通过 DataProvider 或 Data 注入，与 dbloader 输出对齐。
//   - 命名带 `_builtin_` 前缀，避免与真实策略冲突，便于审计日志识别。
//   - 输出结构与 dbloader.go 的 `{policies, roles, subjects}` JSON 完全一致，
//     由 client.initOPARego 注入 OPA inmem store 的 data.<PackageName> 命名空间。
//   - parseEnvoyRBAC 在 P8 已开启 DiscardUnknown:true，因此即便顶层字段不是
//     envoy RBAC schema，rbacData 也只是被赋空 *RBAC，不影响 OPA 数据流。
func (c *Config) defaultData() []byte {
	payload := map[string]any{
		"policies": map[string]any{
			"_builtin_superadmin": map[string]any{
				"code": "_builtin_superadmin",
				"statements": []map[string]any{
					{
						"effect":    "ALLOW",
						"actions":   []string{"*"},
						"resources": []string{"*"},
					},
				},
			},
		},
		"roles": map[string]any{
			"superadmin": map[string]any{
				"parent":   "0",
				"policies": []string{"_builtin_superadmin"},
			},
		},
		"subjects": map[string]any{
			"users":       map[string]any{},
			"groups":      map[string]any{},
			"departments": map[string]any{},
		},
	}
	bs, _ := json.Marshal(payload)
	return bs
}
