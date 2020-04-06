package file

import (
	"bytes"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Exist 用于判断文件是否存在
func Exist(path string) (bool, error) {
	if path == "" {
		return false, fmt.Errorf("file path must set")
	}

	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}

	if !os.IsNotExist(err) {
		return false, err
	}

	return false, nil
}

// WriteString 用于创建新文件并写入内容
func WriteString(path string, s string, perm os.FileMode) error {
	if exist, err := Exist(path); exist && err == nil {
		return fmt.Errorf("%v already exists", path)
	}

	dir := filepath.Dir(path)
	if dir != "" {
		if err := os.MkdirAll(dir, 0777); err != nil {
			return err
		}
	}

	// perm = 0666
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()

	r := strings.NewReader(s)

	_, err = io.Copy(f, r)
	return err
}

// ParseExecute 用于解析模版
func ParseExecute(tmplStr string, data interface{}) (string, error) {
	tmpl, err := template.New("").Parse(tmplStr)
	if err != nil {
		return "", err
	}

	buf := new(bytes.Buffer)
	err = tmpl.Execute(buf, data)
	return buf.String(), err
}
