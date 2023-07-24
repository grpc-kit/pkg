package cfg

import (
	"context"
	"fmt"
	"github.com/minio/minio-go/v7"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

// ProxyConfig xx
//type ProxyConfig struct {
//}

// proxyContextKey 使用自定义类型不对外，防止碰撞冲突
type proxyContextKey int

const (
	ProxyContextHeader proxyContextKey = iota
	ProxyContextBucketLookup
)

// ProxyBucket xx
type ProxyBucket struct {
	logger   *logrus.Entry
	client   *http.Client
	endpoint string
}

// Get xx
func (b *ProxyBucket) Get(ctx context.Context, objectKey string) (io.ReadCloser, ObjstoreAttributes, error) {
	appid := ""
	fileName := "/"

	tmp := strings.Split(objectKey, "/")
	if len(tmp) > 1 {
		appid = tmp[0]
		fileName = strings.Join(tmp[1:], "/")
	}

	headersAny := ctx.Value(ProxyContextHeader)
	bucketLookupAny := ctx.Value(ProxyContextBucketLookup)

	info := ObjstoreAttributes{}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%v/%v", b.endpoint, fileName), nil)
	if err != nil {
		return nil, info, nil
	}

	bucketLookup, ok := bucketLookupAny.(string)
	if !ok {
		return nil, info, fmt.Errorf("objstore proxy context key bucket lookup invalid")
	}

	headers, ok := headersAny.(http.Header)
	if !ok {
		return nil, info, fmt.Errorf("objstore proxy context key headers type invalid")
	}
	for k, v := range headers {
		if k == "Host" {
			if bucketLookup == "dns" {
				req.Host = v[0]
			} else if bucketLookup == "path" {
				req.Host = fmt.Sprintf("%v.%v", appid, v[0])
			}

			continue
		}

		if k == "Content-Length" || k == "Connection" {
			continue
		}

		req.Header.Add(k, v[0])
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, info, err
	}
	// defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, info, minio.ErrorResponse{Code: "NoSuchKey"}
	}

	// header
	for k, v := range resp.Header {
		b.logger.Infof("get header k: %v, v: %v", k, v)
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
	appid := ""
	fileName := "/"

	tmp := strings.Split(objectKey, "/")
	if len(tmp) > 1 {
		appid = tmp[0]
		fileName = strings.Join(tmp[1:], "/")
	}

	headersAny := ctx.Value(ProxyContextHeader)
	bucketLookupAny := ctx.Value(ProxyContextBucketLookup)

	info := ObjstoreAttributes{}
	req, err := http.NewRequest(http.MethodHead, fmt.Sprintf("http://%v/%v", b.endpoint, fileName), nil)
	if err != nil {
		return info, nil
	}

	bucketLookup, ok := bucketLookupAny.(string)
	if !ok {
		return info, fmt.Errorf("objstore proxy context key bucket lookup invalid")
	}

	headers, ok := headersAny.(http.Header)
	if !ok {
		return info, fmt.Errorf("objstore proxy context key headers type invalid")
	}
	for k, v := range headers {
		if k == "Host" {
			if bucketLookup == "dns" {
				req.Host = v[0]
			} else if bucketLookup == "path" {
				req.Host = fmt.Sprintf("%v.%v", appid, v[0])
			}

			continue
		}

		if k == "Content-Length" || k == "Connection" {
			continue
		}

		req.Header.Add(k, v[0])
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
	appid := ""
	fileName := "/"

	tmp := strings.Split(objectKey, "/")
	if len(tmp) > 1 {
		appid = tmp[0]
		fileName = strings.Join(tmp[1:], "/")
	}

	headersAny := ctx.Value(ProxyContextHeader)
	bucketLookupAny := ctx.Value(ProxyContextBucketLookup)

	info := ObjstoreAttributes{}
	req, err := http.NewRequest("PUT", fmt.Sprintf("http://%v/%v", b.endpoint, fileName), r)
	if err != nil {
		return info, nil
	}

	bucketLookup, ok := bucketLookupAny.(string)
	if !ok {
		return info, fmt.Errorf("objstore proxy context key bucket lookup invalid")
	}

	headers, ok := headersAny.(http.Header)
	if !ok {
		return info, fmt.Errorf("objstore proxy context key headers type invalid")
	}
	for k, v := range headers {
		if k == "Host" {
			if bucketLookup == "dns" {
				req.Host = v[0]
			} else if bucketLookup == "path" {
				req.Host = fmt.Sprintf("%v.%v", appid, v[0])
			}

			continue
		}

		if k == "Content-Length" || k == "Connection" {
			continue
		}

		req.Header.Add(k, v[0])
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
	appid := ""
	fileName := "/"

	tmp := strings.Split(objectKey, "/")
	if len(tmp) > 1 {
		appid = tmp[0]
		fileName = strings.Join(tmp[1:], "/")
	}

	headersAny := ctx.Value(ProxyContextHeader)
	bucketLookupAny := ctx.Value(ProxyContextBucketLookup)

	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("http://%v/%v", b.endpoint, fileName), nil)
	if err != nil {
		return err
	}

	bucketLookup, ok := bucketLookupAny.(string)
	if !ok {
		return fmt.Errorf("objstore proxy context key bucket lookup invalid")
	}

	headers, ok := headersAny.(http.Header)
	if !ok {
		return fmt.Errorf("objstore proxy context key headers type invalid")
	}
	for k, v := range headers {
		if k == "Host" {
			if bucketLookup == "dns" {
				req.Host = v[0]
			} else if bucketLookup == "path" {
				req.Host = fmt.Sprintf("%v.%v", appid, v[0])
			}

			continue
		}

		if k == "Content-Length" || k == "Connection" {
			continue
		}

		req.Header.Add(k, v[0])
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
