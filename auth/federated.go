package auth

import (
	"encoding/json"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	ScopeFederatedID       = "federated:id"
	ScopeFederatedUsername = "federated:username"
)

// FederatedClaims 是 JWT 中本次外部认证资料的快照，不依赖 protobuf 类型。
// 可选字段用 nil 表示未提供；没有外部资料时，整个声明也应为 nil。
type FederatedClaims struct {
	ConnectorID string  `json:"connector_id"`
	UserID      *string `json:"user_id,omitempty"`
	Username    *string `json:"username,omitempty"`
	// 只在内存中记录未知键，供本框架的联邦授权校验拒绝；不影响普通上游解码。
	hasUnknownFields bool
}

// UnmarshalJSON 按精确键名解析并记录未知键，保留普通上游字符串扩展的解码能力。
// null 按原字符串解码规则保留为空值；未知键和空值均交由联邦授权校验拒绝。
func (c *FederatedClaims) UnmarshalJSON(data []byte) error {
	var fields map[string]string
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	result := FederatedClaims{ConnectorID: fields["connector_id"]}
	for key, value := range fields {
		switch key {
		case "connector_id":
		case "user_id":
			result.UserID = &value
		case "username":
			result.Username = &value
		default:
			result.hasUnknownFields = true
		}
	}
	*c = result
	return nil
}

// HasFederatedScope 判断 scope 是否申请外部身份资料。
func HasFederatedScope(scope string) bool {
	values := strings.Fields(scope)
	return slices.Contains(values, ScopeFederatedID) || slices.Contains(values, ScopeFederatedUsername)
}

// ValidFederatedUsername 仅检查外部用户名的格式；调用方须保证资料来源真实，
// 不以展示名或拼接生成的标识代替用户名。
func ValidFederatedUsername(username string) bool {
	if username == "" || len(username) > 255 || !utf8.ValidString(username) || strings.TrimSpace(username) != username {
		return false
	}
	return !strings.ContainsFunc(username, unicode.IsControl)
}

// ProjectFederatedClaims 从可信认证来源中选取已获 scope 授权的字段。
// 本方法不负责验证来源身份或批准 OAuth2 客户端权限。
func ProjectFederatedClaims(scope, connectorID, userID, username string) *FederatedClaims {
	if connectorID == "" || userID == "" {
		return nil
	}
	values := strings.Fields(scope)
	claims := &FederatedClaims{ConnectorID: connectorID}
	if slices.Contains(values, ScopeFederatedID) {
		claims.UserID = &userID
	}
	if slices.Contains(values, ScopeFederatedUsername) && ValidFederatedUsername(username) {
		claims.Username = &username
	}
	if claims.UserID == nil && claims.Username == nil {
		return nil
	}
	return claims
}

// ProjectFederatedSnapshot 从已验证的身份快照中选取获授权的字段子集。
// 与原始认证来源不同，仅含用户名的快照无需额外包含 user_id。
// 调用方须先验证凭证并确认 scope 授权；可选值取副本，避免修改原快照。
func ProjectFederatedSnapshot(scope string, snapshot *FederatedClaims) *FederatedClaims {
	if snapshot == nil || snapshot.hasUnknownFields || snapshot.ConnectorID == "" {
		return nil
	}
	values := strings.Fields(scope)
	result := &FederatedClaims{ConnectorID: snapshot.ConnectorID}
	if slices.Contains(values, ScopeFederatedID) && snapshot.UserID != nil && *snapshot.UserID != "" {
		value := *snapshot.UserID
		result.UserID = &value
	}
	if slices.Contains(values, ScopeFederatedUsername) && snapshot.Username != nil && ValidFederatedUsername(*snapshot.Username) {
		value := *snapshot.Username
		result.Username = &value
	}
	if result.UserID == nil && result.Username == nil {
		return nil
	}
	return result
}

// ValidFederatedClaims 检查快照字段是否严格符合授权范围，允许 nil 表示缺少来源。
// 非 nil 对象须包含有效来源和至少一项获授权资料；本方法不负责验签或 OAuth2 授权。
func ValidFederatedClaims(scope string, snapshot *FederatedClaims) bool {
	if snapshot == nil {
		return true
	}
	if snapshot.hasUnknownFields || len(snapshot.ConnectorID) > 32 || !ValidFederatedUsername(snapshot.ConnectorID) {
		return false
	}
	values := strings.Fields(scope)
	if snapshot.UserID != nil && (!slices.Contains(values, ScopeFederatedID) || *snapshot.UserID == "") {
		return false
	}
	if snapshot.Username != nil && (!slices.Contains(values, ScopeFederatedUsername) || !ValidFederatedUsername(*snapshot.Username)) {
		return false
	}
	return snapshot.UserID != nil || snapshot.Username != nil
}
