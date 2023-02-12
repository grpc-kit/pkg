package cfg

import "testing"

func TestSecurity(t *testing.T) {
	t.Run("testSecurityConfig", testSecurityConfig)
}

func testSecurityConfig(t *testing.T) {
	if !lc.Security.Enable {
		t.Errorf("security.enable not true")
	}
	if lc.Security.Authentication == nil {
		t.Errorf("security.authentication is nil")
	}
	if lc.Security.Authorization == nil {
		t.Errorf("security.authorization is nil")
	}
}

func testSecurityTokenHS256(t *testing.T) {
	// 有效 token

	// 非法 token

	// 有效 token，但签名密钥不对

	// 有效 token，但时间过期，必须验证时间

	// 有效 token，但时间过期，忽略时间验证

	// 有效 token, 时间未过期，但 client_id 不匹配

	// 有效 token, 时间未过期，但 issuer 不匹配
}
