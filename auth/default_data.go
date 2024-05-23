package auth

import "fmt"

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
