package admin

import (
	"testing"
	"testing/fstest"
)

// TestSetMicroserviceGatewayYAML_RetainsAssets 验证 setMicroserviceGatewayYAML 保留 assets FS，
// 且 GetMicroserviceGatewaySwaggerJSON 返回该 FS 与资产基名 "microservice"。
func TestSetMicroserviceGatewayYAML_RetainsAssets(t *testing.T) {
	fsys := fstest.MapFS{
		"openapi/microservice.gateway.yaml":   {Data: nil},
		"openapi/microservice.openapiv2.yaml": {Data: []byte("{}")},
		"openapi/microservice.swagger.json":   {Data: []byte(`{"swagger":"2.0","paths":{},"definitions":{}}`)},
	}

	cfg := &config{}
	if err := cfg.setMicroserviceGatewayYAML(fsys); err != nil {
		t.Fatalf("setMicroserviceGatewayYAML: %v", err)
	}
	if cfg.microserviceGatewayAssets == nil {
		t.Fatal("microserviceGatewayAssets not retained")
	}

	a := &KnownAdminAPI{config: cfg}
	assets, name := a.GetMicroserviceGatewaySwaggerJSON()
	if name != "microservice" {
		t.Errorf("name = %q, want microservice", name)
	}
	if assets == nil {
		t.Fatal("getter returned nil assets despite retention")
	}
	// 保留的 FS 能访问 swagger.json（供 AutoBridge loadSwaggerDoc 使用）
	f, err := assets.Open("openapi/microservice.swagger.json")
	if err != nil {
		t.Errorf("open swagger from retained FS: %v", err)
	} else {
		f.Close()
	}
}

// TestGetMicroserviceGatewaySwaggerJSON_NilSafety 验证未加载时返回 (nil, "microservice")。
func TestGetMicroserviceGatewaySwaggerJSON_NilSafety(t *testing.T) {
	var a *KnownAdminAPI
	assets, name := a.GetMicroserviceGatewaySwaggerJSON()
	if name != "microservice" {
		t.Errorf("name = %q, want microservice", name)
	}
	if assets != nil {
		t.Errorf("assets = %v, want nil when not loaded", assets)
	}

	// config 为 nil 的实例同样安全
	assets2, name2 := (&KnownAdminAPI{}).GetMicroserviceGatewaySwaggerJSON()
	if name2 != "microservice" || assets2 != nil {
		t.Errorf("empty KnownAdminAPI: name=%q assets=%v", name2, assets2)
	}
}
