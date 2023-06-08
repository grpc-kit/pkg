package cfg

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/encrypt"
	"github.com/sirupsen/logrus"
)

// ObjstoreConfig 对象存储相关配置
type ObjstoreConfig struct {
	Enable bool     `mapstructure:"enable"`
	Type   string   `mapstructure:"type"`
	Config S3Config `mapstructure:"config"`

	logger *logrus.Entry
	bucket ObjstoreBucket // 对象存储更上一层的抽象化
	client *minio.Client  // 对象存储 minio 的客户端
}

// ObjstoreAttributes 对象属性信息，如：last_modified、etag 等
type ObjstoreAttributes struct {
	// ETag 对象文件内容的 md5 值
	ETag string `json:"etag"`

	// LastModified 对象文件最近被修改时间
	LastModified time.Time `json:"last_modified"`

	// Size 对象文件大小，单位 bytes
	Size int64 `json:"size"`

	// UserMetadata 用户额外定义该对象的元数据，以 "x-amz-meta-*" 请求头返回
	UserMetadata map[string]string `json:"user_metadata"`

	// UserTags 用户定义对象文件关联的标签
	UserTags map[string]string `json:"user_tags"`
}

// ObjstoreBucket 抽象化包装，以简化使用，读写操作权限
type ObjstoreBucket interface {
	io.Closer
	ObjstoreBucketReader

	// Name 获取默认的 bucket 名称
	Name() string

	// Upload 用于上传对象到默认的 bucket 里
	Upload(ctx context.Context, name string, r io.Reader) error

	// Delete 用于删除对象在默认的 bucket 里
	Delete(ctx context.Context, name string) error
}

// ObjstoreBucketReader 抽象化包装，以简化使用，只读操作权限
type ObjstoreBucketReader interface {
	// Get 用于获取默认 bucket 的对象内容
	Get(ctx context.Context, name string) (io.ReadCloser, error)

	// Iter 用于遍历默认 bucket 里的对象文件
	Iter(ctx context.Context, dir string, f func(string) error) error

	// GetRange 用于获取默认 bucket 中对象指定位置的内容
	GetRange(ctx context.Context, name string, off, length int64) (io.ReadCloser, error)

	// Exists 用于判断默认 bucket 是否存在该对象
	Exists(ctx context.Context, name string) (bool, error)

	// Attributes 用于获取默认 bucket 中对象的额外属性
	Attributes(ctx context.Context, name string) (ObjstoreAttributes, error)

	// IsObjNotFoundErr 错误是否为查询的对象不存在
	IsObjNotFoundErr(err error) bool
}

// valid 用于验证对象存储配置是否合法
func (o *ObjstoreConfig) valid() error {
	if strings.ToLower(o.Type) != "s3" {
		return fmt.Errorf("objstore not support type: %v", o.Type)
	}

	if o.Config.Endpoint == "" {
		return fmt.Errorf("no s3 endpoint in config file")
	}

	if o.Config.AccessKey == "" && o.Config.SecretKey != "" {
		return fmt.Errorf("no s3 access_key specified while secret_key is present in config file")
	}

	if o.Config.AccessKey != "" && o.Config.SecretKey == "" {
		return fmt.Errorf("no s3 secret_key specified while access_key is present in config file")
	}

	if o.Config.SSEConfig.Type == "SSE-C" && o.Config.SSEConfig.EncryptionKey == "" {
		return fmt.Errorf("encryption_key must be set if sse_config.type is set to 'SSE-C'")
	}

	if o.Config.SSEConfig.Type == "SSE-KMS" && o.Config.SSEConfig.KMSKeyID == "" {
		return fmt.Errorf("kms_key_id must be set if sse_config.type is set to 'SSE-KMS'")
	}

	return nil
}

// getClient 获取原始的 minio client 资源
func (o *ObjstoreConfig) getClient() (*minio.Client, error) {
	var chain []credentials.Provider

	if o.Config.AccessKey != "" {
		static := &credentials.Static{
			Value: credentials.Value{
				AccessKeyID:     o.Config.AccessKey,
				SecretAccessKey: o.Config.SecretKey,
				SessionToken:    o.Config.SessionToken,
				SignerType:      credentials.SignatureV4,
			},
		}

		switch strings.ToLower(o.Config.SignatureVersion) {
		case "v2":
			static.Value.SignerType = credentials.SignatureV2
		}
		chain = append(chain, static)
	} else {
		chain = append(chain, &credentials.EnvAWS{})
		chain = append(chain, &credentials.EnvMinio{})
		chain = append(chain, &credentials.FileAWSCredentials{})
	}

	rt, err := NewHTTPTransport(o.Config.HTTPConfig)
	if err != nil {
		return nil, err
	}

	bucketLookup := minio.BucketLookupAuto
	switch o.Config.BucketLookupType {
	case "auto":
		bucketLookup = minio.BucketLookupAuto
	case "virtual-hosted":
		bucketLookup = minio.BucketLookupDNS
	case "path":
		bucketLookup = minio.BucketLookupPath
	}

	client, err := minio.New(o.Config.Endpoint, &minio.Options{
		Creds:        credentials.NewChainCredentials(chain),
		Secure:       !o.Config.Insecure,
		Region:       o.Config.Region,
		Transport:    rt,
		BucketLookup: bucketLookup,
	})
	if err != nil {
		return nil, err
	}

	return client, nil
}

// getBucket 获取封装简化的对象
func (o *ObjstoreConfig) getBucket() (*S3Bucket, error) {
	var err error
	var sse encrypt.ServerSide

	if o.Config.SSEConfig.Type != "" {
		switch o.Config.SSEConfig.Type {
		case "SSE-KMS":
			if o.Config.SSEConfig.KMSEncryptionContext == nil {
				o.Config.SSEConfig.KMSEncryptionContext = make(map[string]string)
			}
			sse, err = encrypt.NewSSEKMS(o.Config.SSEConfig.KMSKeyID, o.Config.SSEConfig.KMSEncryptionContext)
			if err != nil {
				o.logger.Errorln(err)
				return nil, fmt.Errorf("initialize s3 client SSE-KMS error")
			}
		case "SSE-C":
			key, err := os.ReadFile(o.Config.SSEConfig.EncryptionKey)
			if err != nil {
				return nil, err
			}
			sse, err = encrypt.NewSSEC(key)
			if err != nil {
				o.logger.Errorln(err)
				return nil, fmt.Errorf("initialize s3 client SSE-C")
			}
		case "SSE-S3":
			sse = encrypt.NewSSE()
		default:
			sseErrMsg := fmt.Errorf("Unsupported type %q was provided. Supported types are SSE-S3, SSE-KMS, SSE-C", o.Config.SSEConfig.Type)
			return nil, sseErrMsg
		}
	}

	if o.Config.ListObjectsVersion != "" && o.Config.ListObjectsVersion != "v1" && o.Config.ListObjectsVersion != "v2" {
		return nil, fmt.Errorf("Initialize s3 client list objects version: Unsupported version %q was provided. Supported values are v1, v2", o.Config.ListObjectsVersion)
	}

	var storageClass string
	amzStorageClassLower := strings.ToLower("X-Amz-Storage-Class")
	for k, v := range o.Config.PutUserMetadata {
		if strings.ToLower(k) == amzStorageClassLower {
			delete(o.Config.PutUserMetadata, k)
			storageClass = v
			break
		}
	}

	bkt := &S3Bucket{
		logger:          o.logger,
		name:            o.Config.Bucket,
		client:          o.client,
		defaultSSE:      sse,
		putUserMetadata: o.Config.PutUserMetadata,
		putUserTags:     o.Config.PutUserTags,
		storageClass:    storageClass,
		partSize:        o.Config.PartSize,
		listObjectsV1:   o.Config.ListObjectsVersion == "v1",
	}

	if bkt.partSize == 0 {
		bkt.partSize = 1024 * 1024 * 64
	}

	return bkt, nil
}

// InitObjstore 初始化对象存储
func (c *LocalConfig) InitObjstore() error {
	// 标准步骤：为空或主动关闭则不开启该功能
	if c.Objstore == nil || !c.Objstore.Enable {
		return nil
	}

	// 标准步骤：验证配置是否合法
	if err := c.Objstore.valid(); err != nil {
		return err
	}

	// 标准步骤：初始化日志组件
	if c.logger != nil {
		c.Objstore.logger = c.logger
	} else {
		c.Objstore.logger = logrus.NewEntry(logrus.New())
	}

	// 初始化对象存储连接
	client, err := c.Objstore.getClient()
	if err != nil {
		return err
	}
	c.Objstore.client = client

	// 对象存储 bucket 初始化
	bucket, err := c.Objstore.getBucket()
	if err != nil {
		return err
	}
	c.Objstore.bucket = bucket

	return nil
}

// GetObjstoreBucket 用于获取对象存储
func (c *LocalConfig) GetObjstoreBucket() (ObjstoreBucket, error) {
	if c.Objstore.bucket != nil {
		return c.Objstore.bucket, nil
	}
	return nil, fmt.Errorf("objstore not found bucket")
}

// GetObjstoreBucketReader 用于获取对象存储
func (c *LocalConfig) GetObjstoreBucketReader() (ObjstoreBucketReader, error) {
	if c.Objstore.bucket != nil {
		return c.Objstore.bucket, nil
	}
	return nil, fmt.Errorf("objstore not found bucket")
}

// GetObjstoreMinioClient 获取内部 minio 客户端连接
func (c *LocalConfig) GetObjstoreMinioClient() (*minio.Client, error) {
	if c.Objstore.client == nil {
		return nil, fmt.Errorf("objstore not found minio client")
	}

	return c.Objstore.client, nil
}
