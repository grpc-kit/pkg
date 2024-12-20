package rpc

import "context"

// contextKey 使用自定义类型不对外，防止碰撞冲突
type contextKey int

const (
	// idTokenKey 用于存放当前jwt的解析后的数据结构
	idTokenKey contextKey = iota

	// usernameKey 用于存放当前用户名，http base对应username，jwt对应email
	usernameKey

	// authenticationTypeKey 用于存放当前认证方式
	authenticationTypeKey

	// groupsKey 用于存放当前用户归属的组列表
	groupsKey
)

// ContextWithIDToken xx
func ContextWithIDToken(parent context.Context, token interface{}) context.Context {
	return context.WithValue(parent, idTokenKey, token)
}

func ContextWithUsername(parent context.Context, username string) context.Context {
	return context.WithValue(parent, usernameKey, username)
}

func ContextWithAuthenticationType(parent context.Context, authType string) context.Context {
	return context.WithValue(parent, authenticationTypeKey, authType)
}

func ContextWithGroups(parent context.Context, groups []string) context.Context {
	return context.WithValue(parent, groupsKey, groups)
}

func GetGroupsFromContext(ctx context.Context) ([]string, bool) {
	groups, ok := ctx.Value(groupsKey).([]string)
	return groups, ok
}

func GetAuthenticationTypeFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(authenticationTypeKey).(string)
	return username, ok
}

func GetUsernameFromContext(ctx context.Context) (string, bool) {
	defaultUser := "anonymous"

	username, ok := ctx.Value(usernameKey).(string)
	if ok && username != "" {
		return username, true
	}

	return defaultUser, false
}

func GetIDTokenFromContext(ctx context.Context) any {
	return ctx.Value(idTokenKey)
}
