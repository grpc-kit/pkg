package adminv1

import (
	"embed"
)

//go:embed openapi/admin.gateway.yaml
//go:embed openapi/admin.openapiv2.yaml
//go:embed openapi/admin.swagger.json
var Assets embed.FS
