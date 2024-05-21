package auth

import "fmt"

// Config xx
type Config struct {
	PackageName string
	OPASDK      *OPASDKConfig
	OPARego     *OPARegoConfig
	OPAEnvoy    *OPAEnvoyPluginConfig
}

type OPASDKConfig struct {
	Config string
}

type OPARegoConfig struct {
	RegoBody []byte
	DataBody []byte
}

type OPAEnvoyPluginConfig struct {
	GRPCAddress string
}

func (c *Config) defaultRego() []byte {
	return []byte(fmt.Sprintf(`
package %s

import future.keywords.if
import future.keywords.in

import data.%s.action
import data.%s.policies

default allow := false

allow if {
#	data.policies[input.appid][input.api_style]
#	input.pattern in data.policies[input.appid].pattern
#	# input.pattern in data.pattern
#  policies["role-appid"].permissions[0].url_path.path.exact == "/"
  input.attributes.request.http.method == "POST"
}
`,
		c.PackageName,
		c.PackageName,
		c.PackageName),
	)
}

func (c *Config) defaultRBAC() []byte {
	return []byte(fmt.Sprintf(`
action: ALLOW
policies:
  "%s":
    permissions:
      - any: true
    principals:
	  - metadata:
		filter: envoy.filters.http.jwt_authn
		path:
		  - key: payload
		  - key: groups
		value:
		  string_match:
			exact:  admin

  "%s":
    permissions:
      - not_rule:
          url_path:
            path:
              exact: "/admin"
    pristinals:
      - any: true
`,
		"admin",
		"guest"),
	)
}
