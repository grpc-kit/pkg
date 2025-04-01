package crypto

import (
	"context"
	"strings"

	"entgo.io/ent"
)

// EncryptedMixin 自动加密/解密带 `_encrypted` 后缀的字段
func EncryptedMixin() ent.Hook {
	return func(next ent.Mutator) ent.Mutator {
		return ent.MutateFunc(func(ctx context.Context, m ent.Mutation) (ent.Value, error) {
			for _, field := range m.Fields() {
				if strings.HasSuffix(field, "_encrypted") {
					if value, ok := m.Field(field); ok {
						if strVal, ok := value.(string); ok {
							encryptedVal, err := EncryptAES(strVal)
							if err != nil {
								return nil, err
							}
							err = m.SetField(field, encryptedVal)
							if err != nil {
								return nil, err
							}
						}
					}
				}
			}
			return next.Mutate(ctx, m)
		})
	}
}

// DecryptEntField 在查询时解密字段
func DecryptEntField() ent.Interceptor {
	return ent.InterceptFunc(func(next ent.Querier) ent.Querier {
		return ent.QuerierFunc(func(ctx context.Context, query ent.Query) (ent.Value, error) {
			// Do something before the query execution.
			value, err := next.Query(ctx, query)
			// Do something after the query execution.
			return value, err
		})
	})
}
