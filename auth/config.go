package auth

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
