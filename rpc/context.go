package rpc

import "context"

// contextKey 使用自定义类型不对外，防止碰撞冲突
type contextKey int

const (
	// idTokenKey 用于存放当前jwt的解析后的数据结构
	idTokenKey contextKey = iota

	// usernameKey 用于存放当前用户名，http base对应username，jwt对应username
	usernameKey

	// authenticationTypeKey 用于存放当前认证方式
	authenticationTypeKey

	// groupsKey 用于存放当前用户归属的组列表
	groupsKey

	// rolesKey 用于存放当前用户用于授权的角色编码列表
	rolesKey

	// userIDKey 用于存放当前用户 ID
	userIDKey
)

// ContextWithIDToken xx
func ContextWithIDToken(parent context.Context, token interface{}) context.Context {
	return context.WithValue(parent, idTokenKey, token)
}

func ContextWithUserID(parent context.Context, userID int64) context.Context {
	return context.WithValue(parent, userIDKey, userID)
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

// ContextWithRoles stores the canonical role codes used for authorization.
func ContextWithRoles(parent context.Context, roles []string) context.Context {
	return context.WithValue(parent, rolesKey, roles)
}

// GetRolesFromContext returns canonical roles. During migration, contexts
// created by old callers fall back to the legacy groups value.
func GetRolesFromContext(ctx context.Context) ([]string, bool) {
	roles, ok := ctx.Value(rolesKey).([]string)
	if ok {
		return roles, true
	}
	groups, ok := ctx.Value(groupsKey).([]string)
	return groups, ok
}

func GetAuthenticationTypeFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(authenticationTypeKey).(string)
	return username, ok
}

func GetUserIDFromContext(ctx context.Context) (int64, bool) {
	defaultUser := 0

	userID, ok := ctx.Value(userIDKey).(int64)
	if ok && userID != 0 {
		return userID, true
	}

	return int64(defaultUser), false
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
