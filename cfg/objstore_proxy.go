package cfg

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/sirupsen/logrus"
)

// ProxyConfig xx
//type ProxyConfig struct {
//}

// proxyContextKey 使用自定义类型不对外，防止碰撞冲突
type proxyContextKey int

const (
	ProxyContextHeader proxyContextKey = iota
	ProxyContextURLStyle
)

// ProxyBucket xx
type ProxyBucket struct {
	logger   *logrus.Entry
	client   *http.Client
	endpoint string
}

// Get 用于获取默认 bucket 的对象内容
func (b *ProxyBucket) Get(ctx context.Context, objectKey string) (io.ReadCloser, ObjstoreAttributes, error) {
	info := ObjstoreAttributes{}

	appid, fileName := b.calcAppidFileName(objectKey)

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%v/%v", b.endpoint, fileName), nil)
	if err != nil {
		return nil, info, nil
	}

	req, err = b.proxyHeaders(ctx, appid, req)
	if err != nil {
		return nil, info, err
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, info, err
	}
	// defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var rawBody []byte
		rawBody, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, info, err
		}
		// resp.Body.Close()

		var s3err minio.ErrorResponse
		if err = json.Unmarshal(rawBody, &s3err); err != nil {
			return nil, info, err
		}

		return nil, info, s3err
	}

	return resp.Body, info, nil
}

// Iter 用于遍历默认 bucket 里的对象文件
func (b *ProxyBucket) Iter(ctx context.Context, dir string, f func(string) error) error {
	return nil
}

// GetRange 用于获取默认 bucket 中对象指定位置的内容
func (b *ProxyBucket) GetRange(ctx context.Context, objectKey string, off, length int64) (io.ReadCloser, ObjstoreAttributes, error) {
	info := ObjstoreAttributes{}
	return nil, info, nil
}

// Exists 用于判断默认 bucket 是否存在该对象
func (b *ProxyBucket) Exists(ctx context.Context, objectKey string) (bool, error) {
	return false, nil
}

// Attributes 用于获取默认 bucket 中对象的额外属性
func (b *ProxyBucket) Attributes(ctx context.Context, objectKey string) (ObjstoreAttributes, error) {
	info := ObjstoreAttributes{}

	appid, fileName := b.calcAppidFileName(objectKey)

	req, err := http.NewRequest(http.MethodHead, fmt.Sprintf("http://%v/%v", b.endpoint, fileName), nil)
	if err != nil {
		return info, nil
	}

	req, err = b.proxyHeaders(ctx, appid, req)
	if err != nil {
		return info, err
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()

	// DEBUG
	for k, v := range resp.Header {
		b.logger.Infof("head object header k: %v, v: %v", k, v)
	}

	return info, nil
}

// IsObjNotFoundErr 错误是否为查询的对象不存在
func (b *ProxyBucket) IsObjNotFoundErr(err error) bool {
	return minio.ToErrorResponse(err).Code == "NoSuchKey"
}

// Name 获取默认的 bucket 名称
func (b *ProxyBucket) Name() string {
	return ""
}

// Upload 用于上传对象到默认的 bucket 里
func (b *ProxyBucket) Upload(ctx context.Context, objectKey string, r io.Reader) (ObjstoreAttributes, error) {
	info := ObjstoreAttributes{}

	appid, fileName := b.calcAppidFileName(objectKey)

	req, err := http.NewRequest("PUT", fmt.Sprintf("http://%v/%v", b.endpoint, fileName), r)
	if err != nil {
		return info, nil
	}

	req, err = b.proxyHeaders(ctx, appid, req)
	if err != nil {
		return info, err
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()

	rawBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return info, err
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("objstore proxy upload object key: %v, fail resp: %v", objectKey, string(rawBody))
		return info, err
	}

	return info, nil
}

// Delete 用于删除对象在默认的 bucket 里
func (b *ProxyBucket) Delete(ctx context.Context, objectKey string) error {
	appid, fileName := b.calcAppidFileName(objectKey)

	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("http://%v/%v", b.endpoint, fileName), nil)
	if err != nil {
		return err
	}

	req, err = b.proxyHeaders(ctx, appid, req)
	if err != nil {
		return err
	}

	_, err = b.client.Do(req)
	if err != nil {
		return err
	}

	return nil
}

// CopyTo 用于拷贝对象在默认 bucket 里
func (b *ProxyBucket) CopyTo(ctx context.Context, srcObjectKey, dstObjectKey string) (ObjstoreAttributes, error) {
	info := ObjstoreAttributes{}
	return info, nil
}

// Close 释放资源
func (b *ProxyBucket) Close() error {
	return nil
}

// 计算 appid 与 fileName
func (b *ProxyBucket) calcAppidFileName(objectKey string) (string, string) {
	appid := ""
	fileName := "/"

	tmp := strings.Split(objectKey, "/")
	if len(tmp) > 1 {
		appid = tmp[0]
		fileName = strings.Join(tmp[1:], "/")
	}

	return appid, fileName
}

// 植入 proxy header 请求头
func (b *ProxyBucket) proxyHeaders(ctx context.Context, appid string, req *http.Request) (*http.Request, error) {
	headersAny := ctx.Value(ProxyContextHeader)
	urlStyleAny := ctx.Value(ProxyContextURLStyle)

	urlStyle, ok := urlStyleAny.(URLStyle)
	if !ok {
		return req, fmt.Errorf("objstore proxy context key bucket lookup invalid")
	}

	headers, ok := headersAny.(http.Header)
	if !ok {
		return req, fmt.Errorf("objstore proxy context key headers invalid")
	}

	for k, v := range headers {
		if k == HTTPHeaderHost {
			if urlStyle == URLStyleVirtualHosted {
				req.Host = v[0]
			} else if urlStyle == URLStylePath {
				req.Host = fmt.Sprintf("%v.%v", appid, v[0])
			}

			continue
		}

		if k == "Content-Length" || k == "Connection" {
			continue
		}

		req.Header.Add(k, v[0])
	}

	return req, nil
}
