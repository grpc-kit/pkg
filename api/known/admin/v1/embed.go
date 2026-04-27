package adminv1

import (
	"embed"
)

//go:embed admin.gateway.yaml
var Assets embed.FS
