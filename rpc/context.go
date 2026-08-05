package rpc

import "context"

// contextKey 使用自定义类型不对外，防止碰撞冲突
type contextKey int

const (
	// tokenClaimsKey 保存已完成认证校验的 Token Claims。
	// 当前主要存放已验证的 Access Token Claims，不保存原始 Token 字符串。
	tokenClaimsKey contextKey = iota

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

// ContextWithTokenClaims 保存已经完成认证校验的 Token Claims。
// rpc 包不依赖具体认证实现，具体 Claims 类型由上层包负责断言。
// Context 中不保存原始 Bearer Token 或签名密钥。
func ContextWithTokenClaims(parent context.Context, claims any) context.Context {
	return context.WithValue(parent, tokenClaimsKey, claims)
}

// GetTokenClaimsFromContext 返回当前请求中已验证的 Token Claims。
// 具体 Claims 类型由调用方负责断言，避免 rpc 包依赖认证业务包。
func GetTokenClaimsFromContext(ctx context.Context) any {
	return ctx.Value(tokenClaimsKey)
}

// ContextWithIDToken 保留用于兼容旧调用方。
// Deprecated: use ContextWithTokenClaims。
func ContextWithIDToken(parent context.Context, token interface{}) context.Context {
	return ContextWithTokenClaims(parent, token)
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

// GetRolesFromContext returns canonical roles. Groups are identity membership
// data and are never used as an authorization fallback.
func GetRolesFromContext(ctx context.Context) ([]string, bool) {
	roles, ok := ctx.Value(rolesKey).([]string)
	return roles, ok
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

// GetIDTokenFromContext 保留用于兼容旧调用方及旧的 IDTokenClaims 值。
// Deprecated: use GetTokenClaimsFromContext。
func GetIDTokenFromContext(ctx context.Context) any {
	return GetTokenClaimsFromContext(ctx)
}
