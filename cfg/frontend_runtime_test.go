package cfg

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
)

func TestHTTPHandlerFrontendServesEmbeddedAdminSwaggerFromPkgAssets(t *testing.T) {
	enabled := true
	disabled := false

	want, err := adminv1.Assets.ReadFile("openapi/admin.swagger.json")
	if err != nil {
		t.Fatalf("read embedded admin swagger from pkg assets: %v", err)
	}

	config := &LocalConfig{
		Frontend: &FrontendConfig{
			Enable: &enabled,
			Interface: FrontendInterface{
				Admin: &WebInterfaceConfig{
					Enabled:   &disabled,
					Embedded:  &enabled,
					HandleURL: "/admin",
				},
				Openapi: &WebInterfaceConfig{
					Enabled:   &enabled,
					Embedded:  &enabled,
					HandleURL: "/openapi-spec",
				},
				Webroot: &WebInterfaceConfig{
					Enabled:   &disabled,
					Embedded:  &enabled,
					HandleURL: "/",
				},
			},
		},
	}

	mux := http.NewServeMux()
	if err := config.HTTPHandlerFrontend(mux, adminv1.Assets); err != nil {
		t.Fatalf("register frontend handlers: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/openapi-spec/admin.swagger.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
	}
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatalf("served admin swagger does not match embedded pkg asset")
	}
}

func TestHTTPHandlerFrontendServesPkgAdminSwaggerWhenProjectAssetMissing(t *testing.T) {
	enabled := true
	disabled := false

	want, err := adminv1.Assets.ReadFile("openapi/admin.swagger.json")
	if err != nil {
		t.Fatalf("read embedded admin swagger from pkg assets: %v", err)
	}

	publicAssets := fstest.MapFS{
		"openapi/microservice.swagger.json": &fstest.MapFile{Data: []byte(`{"swagger":"2.0","paths":{}}`)},
	}

	config := &LocalConfig{
		Frontend: &FrontendConfig{
			Enable: &enabled,
			Interface: FrontendInterface{
				Admin:   &WebInterfaceConfig{Enabled: &disabled, Embedded: &enabled, HandleURL: "/admin"},
				Openapi: &WebInterfaceConfig{Enabled: &enabled, Embedded: &enabled, HandleURL: "/openapi-spec"},
				Webroot: &WebInterfaceConfig{Enabled: &disabled, Embedded: &enabled, HandleURL: "/"},
			},
		},
	}

	mux := http.NewServeMux()
	if err := config.HTTPHandlerFrontend(mux, publicAssets); err != nil {
		t.Fatalf("register frontend handlers: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/openapi-spec/admin.swagger.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
	}
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatalf("served admin swagger does not match pkg fallback asset")
	}
}

func TestHTTPHandlerFrontendServesPkgAdminSwaggerEvenWhenProjectAssetExists(t *testing.T) {
	enabled := true
	disabled := false
	want, err := adminv1.Assets.ReadFile("openapi/admin.swagger.json")
	if err != nil {
		t.Fatalf("read embedded admin swagger from pkg assets: %v", err)
	}
	projectAsset := []byte(`{"swagger":"2.0","info":{"title":"project-openapi"},"paths":{}}`)

	publicAssets := fstest.MapFS{
		"openapi/admin.swagger.json":        &fstest.MapFile{Data: projectAsset},
		"openapi/microservice.swagger.json": &fstest.MapFile{Data: []byte(`{"swagger":"2.0","paths":{}}`)},
	}

	config := &LocalConfig{
		Frontend: &FrontendConfig{
			Enable: &enabled,
			Interface: FrontendInterface{
				Admin:   &WebInterfaceConfig{Enabled: &disabled, Embedded: &enabled, HandleURL: "/admin"},
				Openapi: &WebInterfaceConfig{Enabled: &enabled, Embedded: &enabled, HandleURL: "/openapi-spec"},
				Webroot: &WebInterfaceConfig{Enabled: &disabled, Embedded: &enabled, HandleURL: "/"},
			},
		},
	}

	mux := http.NewServeMux()
	if err := config.HTTPHandlerFrontend(mux, publicAssets); err != nil {
		t.Fatalf("register frontend handlers: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/openapi-spec/admin.swagger.json", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusOK)
	}
	if !bytes.Equal(rec.Body.Bytes(), want) {
		t.Fatalf("served admin swagger does not match pkg embedded asset")
	}
}

func TestHTTPHandlerFrontendDoesNotFallbackToPkgForOtherOpenapiFiles(t *testing.T) {
	enabled := true
	disabled := false

	publicAssets := fstest.MapFS{
		"openapi/microservice.swagger.json": &fstest.MapFile{Data: []byte(`{"swagger":"2.0","paths":{}}`)},
	}

	config := &LocalConfig{
		Frontend: &FrontendConfig{
			Enable: &enabled,
			Interface: FrontendInterface{
				Admin:   &WebInterfaceConfig{Enabled: &disabled, Embedded: &enabled, HandleURL: "/admin"},
				Openapi: &WebInterfaceConfig{Enabled: &enabled, Embedded: &enabled, HandleURL: "/openapi-spec"},
				Webroot: &WebInterfaceConfig{Enabled: &disabled, Embedded: &enabled, HandleURL: "/"},
			},
		},
	}

	mux := http.NewServeMux()
	if err := config.HTTPHandlerFrontend(mux, publicAssets); err != nil {
		t.Fatalf("register frontend handlers: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/openapi-spec/admin.gateway.yaml", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("unexpected status code: got %d want %d", rec.Code, http.StatusNotFound)
	}
}
