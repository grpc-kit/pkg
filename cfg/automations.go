package cfg

import (
	"fmt"
	"io"
	"io/fs"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// AutomationsConfig 流程编排配置
type AutomationsConfig struct {
	// TODO； 引入后导致编译后的二进制代码变大至少 30M
	//clientSet     *kubernetes.Clientset
	//dynamicClient *dynamic.DynamicClient
	restConfig *rest.Config

	// 全局是否启用
	Enable bool `mapstructure:"enable"`

	// 连接 k8s 集群
	Kubernetes KubernetesConfig `mapstructure:"kubernetes"`
}

// KubernetesConfig 连接 k8s 集群
type KubernetesConfig struct {
	// 配置文件路径，既 kubeconfig 文件路径
	ConfigPath string `mapstructure:"config_path"`
	// 结构同 https://pkg.go.dev/k8s.io/client-go@v0.31.2/rest#Config
	RestConfig *struct {
		Host            string `mapstructure:"host"`
		BearerToken     string `mapstructure:"bearer_token"`
		BearerTokenFile string `mapstructure:"bearer_token_file"`
		TLSClientConfig struct {
			Insecure bool `mapstructure:"insecure"`
		} `mapstructure:"tls_client_config"`
	} `mapstructure:"rest_config"`
}

// FlowClientConfig 流程编排客户端配置
type FlowClientConfig struct {
	Config    *rest.Config
	Namespace string
	Appname   string
}

func (c *LocalConfig) initAutomations() error {
	if c.Automations == nil {
		c.Automations = &AutomationsConfig{Enable: false}
	}

	if !c.Automations.Enable {
		return nil
	}

	var err error
	var restConfig *rest.Config

	// 均未配置则使用 in cluster 模式
	if c.Automations.Kubernetes.ConfigPath == "" && c.Automations.Kubernetes.RestConfig == nil {
		restConfig, err = rest.InClusterConfig()
		if err != nil {
			return err
		}
	} else if c.Automations.Kubernetes.ConfigPath != "" {
		restConfig, err = clientcmd.BuildConfigFromFlags("", c.Automations.Kubernetes.ConfigPath)
		if err != nil {
			return err
		}
	} else if c.Automations.Kubernetes.RestConfig != nil {
		if c.Automations.Kubernetes.RestConfig.Host == "" {
			return fmt.Errorf("automations.kubernetes.rest_config.host must specified")
		}

		restConfig = &rest.Config{
			Host:        c.Automations.Kubernetes.RestConfig.Host,
			BearerToken: c.Automations.Kubernetes.RestConfig.BearerToken,
			TLSClientConfig: rest.TLSClientConfig{
				Insecure: c.Automations.Kubernetes.RestConfig.TLSClientConfig.Insecure,
			},
		}
	}

	c.Automations.restConfig = restConfig
	return nil
}

func (a *AutomationsConfig) defaultValues() {
	return
}

// GetScriptSource 用于获取脚本内容，从 db 或本地中
func (fcc *FlowClientConfig) GetScriptSource(assets fs.FS, name string) (string, error) {
	filePath := fmt.Sprintf("%v", name)

	f, err := assets.Open(filePath)
	if err != nil {
		return "", err
	}
	source, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}

	return string(source), nil
}
