package auth

import "fmt"

func (c *Config) defaultRego() []byte {
	return []byte(fmt.Sprintf(`
package %s

# import rego.v1

import future.keywords.if
import future.keywords.in

import data.%s.action
import data.%s.policies

default allow := false

# 允许所有客户端请求以下 url 前缀地址
allow if {
    some url in ["ping"]
    url == input.parsed_path[0]
}

# 仅允许特定内网访问以下 url 前缀地址
allow if {
    some url in ["version", "openapi-spec"]
    url == input.parsed_path[0]

    some cidr in ["127.0.0.0/8", "100.64.0.0/10", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    net.cidr_contains(cidr, input.attributes.source.address.socketAddress.address)
}

# 仅允许特定内网且必须登录后才可访问管理后台
allow if {
    input.parsed_path[0] == "admin"

    some cidr in ["127.0.0.0/8", "100.64.0.0/10", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    net.cidr_contains(cidr, input.attributes.source.address.socketAddress.address)

    some x, _ in policies
    x in data.%s.access_token.payload.groups
}

# 所有接口请求必须认证且邮箱地址必须是验证过
allow if {
    input.parsed_path[0] == "api"

    data.%s.access_token.payload.email_verified == true
}

# 解析 jwt token 这里不做签名串验证
access_token := {"payload": payload} if {
    [_, encoded] := split(input.attributes.request.http.headers.authorization, " ")
    [header, payload, sig] := io.jwt.decode(encoded)
}
`,
		c.PackageName,
		c.PackageName,
		c.PackageName,
		c.PackageName,
		c.PackageName),
	)
}
