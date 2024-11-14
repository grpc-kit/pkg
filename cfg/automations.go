package cfg

import (
	"fmt"

	"k8s.io/client-go/rest"
)

// AutomationsConfig 流程编排配置
type AutomationsConfig struct {
	// TODO； 引入后导致编译后的二进制代码变大至少 30M
	//clientSet     *kubernetes.Clientset
	//dynamicClient *dynamic.DynamicClient

	// 全局是否启用
	Enable bool `mapstructure:"enable"`

	// 连接 k8s 集群
	Kubernetes KubernetesConfig `mapstructure:"kubernetes"`
}

// KubernetesConfig 连接 k8s 集群
type KubernetesConfig struct {
	// 配置文件路径，既 kubeconfig 文件路径
	ConfigPath string `mapstructure:"config_path"`
}

func (c *LocalConfig) initAutomations() error {
	if c.Automations == nil {
		c.Automations = &AutomationsConfig{Enable: false}
	}

	if !c.Automations.Enable {
		return nil
	}

	x := rest.Config{}
	c.logger.Infof("rest config: %v", x)

	if c.Automations.Kubernetes.ConfigPath == "" {
		return fmt.Errorf("must set kubeconfig path")
	}

	/*
		config, err := clientcmd.BuildConfigFromFlags("", c.Automations.Kubernetes.ConfigPath)
		if err != nil {
			return err
		}

		cs, err := kubernetes.NewForConfig(config)
		if err != nil {
			return err
		}
		c.Automations.clientSet = cs

		dc, err := dynamic.NewForConfig(config)
		if err != nil {
			return err
		}
		c.Automations.dynamicClient = dc
	*/

	return nil
}

func (a *AutomationsConfig) defaultValues() {
	return
}
