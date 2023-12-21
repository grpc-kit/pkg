package cfg

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path"
)

// FrontendConfig xx
type FrontendConfig struct {
	Admin   WebComponentConfig `mapstructure:"admin"`
	Openapi WebComponentConfig `mapstructure:"openapi"`
	Webroot WebComponentConfig `mapstructure:"webroot"`
}

// WebComponentConfig xx
type WebComponentConfig struct {
	Enabled *bool `mapstructure:"enabled"`
	Embed   bool  `mapstructure:"embed"`
}

func (f FrontendConfig) web(mux *http.ServeMux, assets fs.FS) error {
	// assets 内容包含以下三个目录： openapi/ admin/ webroot/
	// 通过 fs.Sub 函数把各个子目录提取出来，此时内容均为 / 目录
	// 在使用 http.StripPrefix 把 mux.Handle 前面的 url 给过滤掉

	openapiData, err := fs.Sub(assets, "openapi")
	adminData, err := fs.Sub(assets, "admin")
	webrootData, err := fs.Sub(assets, "webroot")

	mux.Handle("/openapi-spec/", http.StripPrefix("/openapi-spec/", http.FileServer(http.FS(openapiData))))
	mux.Handle("/admin/", http.StripPrefix("/admin/", http.FileServer(http.FS(adminData))))
	mux.Handle("/", http.FileServer(testFileSystem{http.FS(webrootData)}))

	return err
}

type testFileSystem struct {
	http.FileSystem
}

func (fsys testFileSystem) Open(name string) (http.File, error) {
	file, err := fsys.FileSystem.Open(name)

	if err != nil {
		// 仅针对 *.html 的文件才做 404 页面
		if errors.Is(err, os.ErrNotExist) && path.Ext(name) == ".html" {
			file, err = fsys.FileSystem.Open("404.html")
			return file, err
		}

		return nil, err
	}

	return file, err
}
