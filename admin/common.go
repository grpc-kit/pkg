package admin

import (
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// I18NNameJSON 用于获取 i18n name 的 json 结果
func I18NNameJSON(i18n *adminv1.I18NName) string {
	if i18n == nil {
		return ""
	}

	rawBody, err := protojson.Marshal(i18n)
	if err != nil {
		return ""
	}

	return string(rawBody)
}

// I18NNameParse 用于解析 json 为 i18n name 结构
func I18NNameParse(rawBody string) *adminv1.I18NName {
	result := &adminv1.I18NName{}

	if rawBody == "" {
		return result
	}

	_ = protojson.Unmarshal([]byte(rawBody), result)

	return result
}
