package cfg

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"os"
	"path"
	"strings"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/encrypt"
	"github.com/sirupsen/logrus"
)

// SSEConfig 用于配置对象存储服务端加密
// https://docs.aws.amazon.com/kms/latest/developerguide/services-s3.html#s3-encryption-context
type SSEConfig struct {
	Type                 string            `mapstructure:"type" yaml:"type"`
	KMSKeyID             string            `mapstructure:"kms_key_id" yaml:"kms_key_id"`
	KMSEncryptionContext map[string]string `mapstructure:"kms_encryption_context" yaml:"kms_encryption_context"`
	EncryptionKey        string            `mapstructure:"encryption_key" yaml:"encryption_key"`
}

// S3Config 对象存储 S3 的标准配置
type S3Config struct {
	Bucket             string            `mapstructure:"bucket" yaml:"bucket"`
	Endpoint           string            `mapstructure:"endpoint" yaml:"endpoint"`
	Region             string            `mapstructure:"region" yaml:"region"`
	AccessKey          string            `mapstructure:"access_key" yaml:"access_key"`
	Insecure           bool              `mapstructure:"insecure" yaml:"insecure"`
	SecretKey          string            `mapstructure:"secret_key" yaml:"secret_key"`
	SessionToken       string            `mapstructure:"session_token" yaml:"session_token"`
	PutUserMetadata    map[string]string `mapstructure:"put_user_metadata" yaml:"put_user_metadata"`
	PutUserTags        map[string]string `mapstructure:"put_user_tags" yaml:"put_user_tags"`
	HTTPConfig         HTTPConfig        `mapstructure:"http_config" yaml:"http_config"`
	SignatureVersion   string            `mapstructure:"signature_version" yaml:"signature_version"`
	ListObjectsVersion string            `mapstructure:"list_objects_version" yaml:"list_objects_version"`
	BucketLookupType   string            `mapstructure:"bucket_lookup_type" yaml:"bucket_lookup_type"`
	PartSize           uint64            `mapstructure:"part_size" yaml:"part_size"`
	SSEConfig          SSEConfig         `mapstructure:"sse_config" yaml:"sse_config"`
}

// S3Bucket 用于实现 ObjstoreBucket 简化对象存储接口的使用
type S3Bucket struct {
	logger          *logrus.Entry
	name            string
	client          *minio.Client
	defaultSSE      encrypt.ServerSide
	putUserMetadata map[string]string
	putUserTags     map[string]string
	storageClass    string
	partSize        uint64
	listObjectsV1   bool
}

// Name 获取默认的 bucket 名称
func (b *S3Bucket) Name() string {
	return b.name
}

// Iter 用于遍历默认 bucket 里的对象
func (b *S3Bucket) Iter(ctx context.Context, dir string, f func(string) error) error {
	dirDelim := "/"
	if dir != "" {
		dir = strings.TrimSuffix(dir, dirDelim) + dirDelim
	}

	opts := minio.ListObjectsOptions{
		Prefix:    dir,
		Recursive: true,
		UseV1:     b.listObjectsV1,
	}

	for object := range b.client.ListObjects(ctx, b.name, opts) {
		if object.Err != nil {
			return object.Err
		}
		if object.Key == "" {
			continue
		}
		if object.Key == dir {
			continue
		}
		if err := f(object.Key); err != nil {
			return err
		}
	}

	return nil
}

// getRange 用于获取对象范围数据
func (b *S3Bucket) getRange(ctx context.Context, objectKey string, start, end int64) (io.ReadCloser, ObjstoreAttributes, error) {
	a := ObjstoreAttributes{}
	opts := &minio.GetObjectOptions{ServerSideEncryption: b.defaultSSE}
	if end != -1 {
		if err := opts.SetRange(start, end); err != nil {
			return nil, a, err
		}
	} else if start > 0 {
		if err := opts.SetRange(start, 0); err != nil {
			return nil, a, err
		}
	}
	r, err := b.client.GetObject(ctx, b.name, objectKey, *opts)
	if err != nil {
		return r, a, err
	}

	// NotFoundObject error is revealed only after first Read. This does the initial GetRequest. Prefetch this here
	// for convenience.
	if _, err = r.Read(nil); err != nil {
		return r, a, err
	}

	i, err := r.Stat()
	if err != nil {
		return r, a, err
	}

	a.Size = i.Size
	a.LastModified = i.LastModified
	a.UserTags = i.UserTags
	a.UserMetadata = i.UserMetadata
	a.ETag = i.ETag

	if a.UserMetadata == nil {
		a.UserMetadata = make(map[string]string, 0)
	}
	if i.ContentType != "" {
		a.UserMetadata["Content-Type"] = i.ContentType
	}

	return r, a, nil
}

// Get 用于获取默认 bucket 的对象内容
func (b *S3Bucket) Get(ctx context.Context, objectKey string) (io.ReadCloser, ObjstoreAttributes, error) {
	return b.getRange(ctx, objectKey, 0, -1)
}

// GetRange 用于获取默认 bucket 中对象指定位置的内容
func (b *S3Bucket) GetRange(ctx context.Context, objectKey string, start, end int64) (io.ReadCloser, ObjstoreAttributes, error) {
	return b.getRange(ctx, objectKey, start, end)
}

// Exists 用于判断默认 bucket 是否存在该对象Exists 用于判断默认 bucket 是否存在该对象
func (b *S3Bucket) Exists(ctx context.Context, objectKey string) (bool, error) {
	_, err := b.client.StatObject(ctx, b.name, objectKey, minio.StatObjectOptions{})
	if err != nil {
		if b.IsObjNotFoundErr(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat s3 object: %v", err)
	}

	return true, nil
}

// Upload 用于上传对象到默认的 bucket 里
func (b *S3Bucket) Upload(ctx context.Context, objectKey string, r io.Reader) (ObjstoreAttributes, error) {
	size, err := b.tryToGetSize(r)
	if err != nil {
		b.logger.Errorf("could not guess file size for multipart upload; upload might be not optimized, name: %v, err: %v", objectKey, err)
		size = -1
	}

	var attrs ObjstoreAttributes

	contentType := mime.TypeByExtension(path.Ext(objectKey))
	if contentType == "" {
		contentType = "application/octet-stream"
	}

	partSize := b.partSize
	if size < int64(partSize) {
		partSize = 0
	}
	info, err := b.client.PutObject(
		ctx,
		b.name,
		objectKey,
		r,
		size,
		minio.PutObjectOptions{
			ContentType:          contentType,
			PartSize:             partSize,
			ServerSideEncryption: b.defaultSSE,
			UserMetadata:         b.putUserMetadata,
			UserTags:             b.putUserTags,
			StorageClass:         b.storageClass,
			NumThreads:           4,
		},
	)
	if err != nil {
		return attrs, fmt.Errorf("upload s3 object: %v", err)
	}

	attrs.ETag = info.ETag
	attrs.Size = info.Size
	attrs.LastModified = info.LastModified
	attrs.VersionID = info.VersionID

	return attrs, nil
}

// Attributes 用于获取默认 bucket 中对象的额外属性
func (b *S3Bucket) Attributes(ctx context.Context, objectkey string) (ObjstoreAttributes, error) {
	objInfo, err := b.client.StatObject(ctx, b.name, objectkey, minio.StatObjectOptions{})
	if err != nil {
		return ObjstoreAttributes{}, err
	}

	return ObjstoreAttributes{
		Size:         objInfo.Size,
		LastModified: objInfo.LastModified,
		UserTags:     objInfo.UserTags,
		UserMetadata: objInfo.UserMetadata,
		ETag:         objInfo.ETag,
		VersionID:    objInfo.VersionID,
	}, nil
}

// Delete 用于删除对象在默认的 bucket 里
func (b *S3Bucket) Delete(ctx context.Context, objectKey string) error {
	return b.client.RemoveObject(ctx, b.name, objectKey, minio.RemoveObjectOptions{})
}

// IsObjNotFoundErr 判断释放为对象不存在
func (b *S3Bucket) IsObjNotFoundErr(err error) bool {
	return minio.ToErrorResponse(err).Code == "NoSuchKey"
}

// CopyTo 用于拷贝同 bucket 下的对象文件，对象名不以 '/' 开头
func (b *S3Bucket) CopyTo(ctx context.Context, srcObjectKey, dstObjectKey string) (ObjstoreAttributes, error) {
	info := ObjstoreAttributes{}

	srcOpt := minio.CopySrcOptions{
		Bucket: b.name,
		Object: srcObjectKey,
	}
	dstOpt := minio.CopyDestOptions{
		Bucket:          b.name,
		Object:          dstObjectKey,
		ReplaceMetadata: true,
	}

	resp, err := b.client.CopyObject(ctx, dstOpt, srcOpt)
	if err != nil {
		return info, err
	}

	info.ETag = resp.ETag
	info.LastModified = resp.LastModified
	info.Size = resp.Size

	return info, nil
}

// Close 释放资源
func (b *S3Bucket) Close() error {
	return nil
}

// tryToGetSize 用于分块上传，计算文件的大小
func (b *S3Bucket) tryToGetSize(r io.Reader) (int64, error) {
	switch f := r.(type) {
	case *os.File:
		fileInfo, err := f.Stat()
		if err != nil {
			return 0, fmt.Errorf("os.File.Stat(): %v", err)
		}
		return fileInfo.Size(), nil
	case *bytes.Buffer:
		return int64(f.Len()), nil
	case *bytes.Reader:
		return int64(f.Len()), nil
	case *strings.Reader:
		return f.Size(), nil
	}

	return 0, fmt.Errorf("unsupported type of io.Reader: %T", r)
}
