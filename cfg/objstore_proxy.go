package cfg

import (
	"context"
	"fmt"
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
	info := ObjstoreAttributes{}

	return nil, info, nil
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
	return info, nil
}

// IsObjNotFoundErr 错误是否为查询的对象不存在
func (b *ProxyBucket) IsObjNotFoundErr(err error) bool {
	return false
}

// Name 获取默认的 bucket 名称
func (b *ProxyBucket) Name() string {
	return ""
}

// Upload 用于上传对象到默认的 bucket 里
func (b *ProxyBucket) Upload(ctx context.Context, objectKey string, r io.Reader) (ObjstoreAttributes, error) {
	info := ObjstoreAttributes{}

	b.logger.Infof("proxy put object: %v, endpoint: %v", objectKey, b.endpoint)

	tmp := strings.Split(objectKey, "/")
	appid := tmp[0]
	fileName := strings.Join(tmp[1:], "/")

	headersAny := ctx.Value(ProxyContextHeader)
	bucketLookupAny := ctx.Value(ProxyContextBucketLookup)

	req, err := http.NewRequest("PUT", fmt.Sprintf("http://%v/%v", b.endpoint, fileName), r)
	if err != nil {
		return info, nil
	}

	bucketLookup, _ := bucketLookupAny.(string)

	val, ok := headersAny.(http.Header)
	if ok {
		b.logger.Infof("headers ok: %v", ok)
	}
	for k, v := range val {
		if k == "Host" {
			if bucketLookup == "dns" {
				req.Host = v[0]
			} else if bucketLookup == "path" {
				req.Host = fmt.Sprintf("%v.%v", appid, v[0])
			}

			continue
		}

		/*
			if k == "Content-Length" || k == "Connection" {
				continue
			}
		*/

		b.logger.Infof("header k: %v, v: %v", k, v)

		req.Header.Add(k, v[0])
	}

	for k, v := range req.Header {
		b.logger.Infof("new header k: %v, v: %v", k, v)
	}

	resp, err := b.client.Do(req)

	// DEBUG
	b.logger.Infof("Upload host1: %v, host2: %v, err: %v", req.Host, req.URL.Host, err)

	if err != nil {
		return info, err
	}

	rawBody, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return info, err
	}

	return info, nil
}

// Delete 用于删除对象在默认的 bucket 里
func (b *ProxyBucket) Delete(ctx context.Context, objectKey string) error {
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
