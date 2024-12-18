package cfg

import (
	"fmt"
	"math/rand"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
)

// initServices 用于基础服务初始化配置检查
func (c *LocalConfig) initServices() error {
	// 验证 service_code 关键属性是否在
	if c.Services == nil || c.Services.ServiceCode == "" {
		return fmt.Errorf("unknow service_code")
	}

	if c.Services.RootPath == "" {
		c.Services.RootPath = "service"
	}
	if c.Services.Namespace == "" {
		c.Services.Namespace = "default"
	}
	if c.Services.APIEndpoint == "" {
		c.Services.APIEndpoint = "api.grpc-kit.com"
	}

	c.Services.jsonMarshal = protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: true,
	}
	c.Services.jsonUnmarshal = protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}

	// 初始化默认设置
	if c.Services.GRPCAddress == "" {
		// TODO；如果 10081 端口已被占用，自动切换其他端口
		rand.Seed(time.Now().UnixNano())
		c.Services.GRPCAddress = fmt.Sprintf("127.0.0.1:%v", 10081+rand.Intn(6000))
	}
	if c.Services.PublicAddress == "" {
		// 支持环境变量设置微服务地址
		if addr := os.Getenv("GRPC_KIT_PUHLIC_IP"); addr != "" {
			// 获取服务端口
			tmp := strings.Split(c.Services.GRPCAddress, ":")
			if len(tmp) == 2 {
				c.Services.PublicAddress = fmt.Sprintf("%v:%v", addr, tmp[1])
			} else {
				c.Services.PublicAddress = c.Services.GRPCAddress
			}
		} else {
			c.Services.PublicAddress = c.Services.GRPCAddress
		}
	}

	return nil
}
