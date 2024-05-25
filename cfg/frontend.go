package cfg

import (
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
)

// FrontendConfig 用于表示前端配置
type FrontendConfig struct {
	Enable    *bool             `mapstructure:"enable"`
	Interface FrontendInterface `mapstructure:"interface"`
}

// FrontendInterface 表示前端界面配置
type FrontendInterface struct {
	Admin   *WebInterfaceConfig `mapstructure:"admin"`   // 用户管理后台配置
	Openapi *WebInterfaceConfig `mapstructure:"openapi"` // 后端 API 接口文档
	Webroot *WebInterfaceConfig `mapstructure:"webroot"` // 站点根路径配置
}

// WebInterfaceConfig 表示前端界面组件配置
type WebInterfaceConfig struct {
	Enabled   *bool  `mapstructure:"enabled"`    // 是否启用该服务
	Embedded  *bool  `mapstructure:"embedded"`   // 是否嵌入到编译的二进制
	HandleURL string `mapstructure:"handle_url"` // 注册服务对应的 URL 地址
	Tracing   bool   `mapstructure:"tracing"`    // 是否接入可观测性的链路跟踪服务
}

type customFileSystem struct {
	http.FileSystem
}

func (f customFileSystem) Open(name string) (http.File, error) {
	file, err := f.FileSystem.Open(name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		// 非文件未找到错误
		return nil, err
	} else if errors.Is(err, os.ErrNotExist) {
		// 针对 .html 扩展后缀的文件做 404 页面展示
		ext := path.Ext(name)
		switch ext {
		// 如果文件没有扩展名，且目录下面不存在 index.html 则做 404 页面展示，这样避免直接列出目录
		case "":
			file, err = f.FileSystem.Open(fmt.Sprintf("%v/index.html", name))
			if err != nil && errors.Is(err, os.ErrNotExist) {
				file, err = f.FileSystem.Open("404.html")
			}
		case ".html":
			// TODO; 404.html 文件可实现自定义
			file, err = f.FileSystem.Open("404.html")
		default:
			return file, err
		}
	}

	return file, err
}

// initFrontend 初始化前端服务
func (c *LocalConfig) initFrontend() error {
	var enableVal = true

	if c.Frontend == nil {
		c.Frontend = &FrontendConfig{
			Enable: &enableVal,
		}
	}

	if c.Frontend.Enable == nil {
		c.Frontend.Enable = &enableVal
	}

	c.Frontend.defaultValues()

	return nil
}

func (f *FrontendConfig) defaultValues() {
	f.defaultValueInterfaceAdmin(f.Interface.Admin)
	f.defaultValueInterfaceOpenapi(f.Interface.Openapi)
	f.defaultValueInterfaceWebroot(f.Interface.Webroot)
}

func (f *FrontendConfig) defaultValueInterfaceAdmin(v *WebInterfaceConfig) {
	var enableVal = true
	var disalbeVal = false

	if v == nil {
		f.Interface.Admin = &WebInterfaceConfig{
			Enabled:   &disalbeVal,
			Embedded:  &enableVal,
			HandleURL: "/admin",
		}
		return
	}

	if v.Embedded == nil {
		v.Embedded = &enableVal
	}
	if v.Enabled == nil {
		v.Enabled = &disalbeVal
	}
	if v.HandleURL == "" {
		v.HandleURL = "/admin"
	}
}

func (f *FrontendConfig) defaultValueInterfaceOpenapi(v *WebInterfaceConfig) {
	var enableVal = true

	if v == nil {
		f.Interface.Openapi = &WebInterfaceConfig{
			Enabled:   &enableVal,
			Embedded:  &enableVal,
			HandleURL: "/openapi-spec",
		}
		return
	}

	if v.Embedded == nil {
		v.Embedded = &enableVal
	}
	if v.Enabled == nil {
		v.Enabled = &enableVal
	}
	if v.HandleURL == "" {
		v.HandleURL = "/openapi-spec"
	}
}

func (f *FrontendConfig) defaultValueInterfaceWebroot(v *WebInterfaceConfig) {
	var enableVal = true
	var disalbeVal = false

	if v == nil {
		f.Interface.Webroot = &WebInterfaceConfig{
			Enabled:   &disalbeVal,
			Embedded:  &enableVal,
			HandleURL: "/",
		}
		return
	}

	if v.Embedded == nil {
		v.Embedded = &enableVal
	}
	if v.Enabled == nil {
		v.Enabled = &disalbeVal
	}
	if v.HandleURL == "" {
		v.HandleURL = "/"
	}
}

// Webroot 获取 webroot 的handler
func (f *FrontendConfig) getHandler(assets fs.FS, kind string) (http.Handler, string, bool, error) {
	// assets 内容包含以下三个目录： openapi/ admin/ webroot/
	// 通过 fs.Sub 函数把各个子目录提取出来，此时内容均为 / 目录
	// 在使用 http.StripPrefix 把 mux.Handle 前面的 url 给过滤掉

	// 如果不使用 embedded 则静态文件存放在目录 public/{openapi,admin,webroot} 下面

	enabled := false
	embedded := true
	handleURL := ""

	switch kind {
	case "admin":
		enabled = *f.Interface.Admin.Enabled
		embedded = *f.Interface.Admin.Embedded
		handleURL = f.Interface.Admin.HandleURL
	case "openapi":
		enabled = *f.Interface.Openapi.Enabled
		embedded = *f.Interface.Openapi.Embedded
		handleURL = f.Interface.Openapi.HandleURL
	case "webroot":
		enabled = *f.Interface.Webroot.Enabled
		embedded = *f.Interface.Webroot.Embedded
		handleURL = f.Interface.Webroot.HandleURL
	default:
		return nil, "", false, fmt.Errorf("not support kind: %v", kind)
	}

	if !enabled {
		return nil, "", false, nil
	}

	content, err := fs.Sub(assets, kind)
	if err != nil {
		return nil, "", true, err
	}

	var handle http.Handler
	if embedded {
		handle = http.FileServer(customFileSystem{http.FS(content)})
	} else {
		handle = http.FileServer(customFileSystem{http.Dir(fmt.Sprintf("./public/%v/", kind))})
	}
	if err != nil {
		return handle, "", true, err
	}

	if handleURL != "/" {
		handleURL = fmt.Sprintf("%v/", handleURL)
		handle = http.StripPrefix(handleURL, handle)
	}

	return handle, handleURL, true, nil
}
