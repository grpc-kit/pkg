package adminv1

import (
	"embed"
)

//go:embed openapi/admin.gateway.yaml
//go:embed openapi/admin.openapiv2.yaml
var Assets embed.FS
