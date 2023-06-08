package cfg

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
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
func (b *S3Bucket) getRange(ctx context.Context, name string, off, length int64) (io.ReadCloser, error) {
	opts := &minio.GetObjectOptions{ServerSideEncryption: b.defaultSSE}
	if length != -1 {
		if err := opts.SetRange(off, off+length-1); err != nil {
			return nil, err
		}
	} else if off > 0 {
		if err := opts.SetRange(off, 0); err != nil {
			return nil, err
		}
	}
	r, err := b.client.GetObject(ctx, b.name, name, *opts)
	if err != nil {
		return nil, err
	}

	// NotFoundObject error is revealed only after first Read. This does the initial GetRequest. Prefetch this here
	// for convenience.
	if _, err := r.Read(nil); err != nil {
		// First GET Object request error.
		return nil, err
	}

	return r, nil
}

// Get 用于获取默认 bucket 的对象内容
func (b *S3Bucket) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	return b.getRange(ctx, name, 0, -1)
}

// GetRange 用于获取默认 bucket 中对象指定位置的内容
func (b *S3Bucket) GetRange(ctx context.Context, name string, off, length int64) (io.ReadCloser, error) {
	return b.getRange(ctx, name, off, length)
}

// Exists 用于判断默认 bucket 是否存在该对象Exists 用于判断默认 bucket 是否存在该对象
func (b *S3Bucket) Exists(ctx context.Context, name string) (bool, error) {
	_, err := b.client.StatObject(ctx, b.name, name, minio.StatObjectOptions{})
	if err != nil {
		if b.IsObjNotFoundErr(err) {
			return false, nil
		}
		return false, fmt.Errorf("stat s3 object: %v", err)
	}

	return true, nil
}

// Upload 用于上传对象到默认的 bucket 里
func (b *S3Bucket) Upload(ctx context.Context, name string, r io.Reader) error {
	size, err := b.tryToGetSize(r)
	if err != nil {
		b.logger.Errorf("could not guess file size for multipart upload; upload might be not optimized, name: %v, err: %v", name, err)
		size = -1
	}

	partSize := b.partSize
	if size < int64(partSize) {
		partSize = 0
	}
	if _, err := b.client.PutObject(
		ctx,
		b.name,
		name,
		r,
		size,
		minio.PutObjectOptions{
			PartSize:             partSize,
			ServerSideEncryption: b.defaultSSE,
			UserMetadata:         b.putUserMetadata,
			UserTags:             b.putUserTags,
			StorageClass:         b.storageClass,
			NumThreads:           4,
		},
	); err != nil {
		return fmt.Errorf("upload s3 object: %v", err)
	}

	return nil
}

// Attributes 用于获取默认 bucket 中对象的额外属性
func (b *S3Bucket) Attributes(ctx context.Context, name string) (ObjstoreAttributes, error) {
	objInfo, err := b.client.StatObject(ctx, b.name, name, minio.StatObjectOptions{})
	if err != nil {
		return ObjstoreAttributes{}, err
	}

	return ObjstoreAttributes{
		Size:         objInfo.Size,
		LastModified: objInfo.LastModified,
		UserTags:     objInfo.UserTags,
		UserMetadata: objInfo.UserMetadata,
		ETag:         objInfo.ETag,
	}, nil
}

// Delete 用于删除对象在默认的 bucket 里
func (b *S3Bucket) Delete(ctx context.Context, name string) error {
	return b.client.RemoveObject(ctx, b.name, name, minio.RemoveObjectOptions{})
}

// IsObjNotFoundErr 判断释放为对象不存在
func (b *S3Bucket) IsObjNotFoundErr(err error) bool {
	return minio.ToErrorResponse(err).Code == "NoSuchKey"
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
