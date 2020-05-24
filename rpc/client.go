package rpc

import (
	"context"
	"fmt"

	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// Client 客户端
type Client struct {
	logger           *logrus.Entry
	config           *Config
	opts             []grpc.DialOption
	unaryIntercepts  []grpc.UnaryClientInterceptor
	streamIntercepts []grpc.StreamClientInterceptor
}

// NewClient 新建客户端
func NewClient(conf *Config) *Client {
	c := new(Client)
	c.config = conf
	return c
}

// UseDialOption 用于添加自定义连接参数
func (c *Client) UseDialOption(opts ...grpc.DialOption) *Client {
	c.opts = append(c.opts, opts...)
	return c
}

// UseUnaryInterceptor 用于添加自定义客户端一元拦截器
func (c *Client) UseUnaryInterceptor(handlers ...grpc.UnaryClientInterceptor) *Client {
	c.unaryIntercepts = append(c.unaryIntercepts, handlers...)
	return c
}

// UseStreamInterceptor 用于添加自定义客户端流拦截器
func (c *Client) UseStreamInterceptor(handlers ...grpc.StreamClientInterceptor) *Client {
	c.streamIntercepts = append(c.streamIntercepts, handlers...)
	return c
}

// Dial 用于创建连接
func (c *Client) Dial(ctx context.Context, scode string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	c.opts = append(c.opts, opts...)
	c.opts = append(c.opts, grpc.WithUnaryInterceptor(grpcmiddleware.ChainUnaryClient(c.unaryIntercepts...)))
	c.opts = append(c.opts, grpc.WithStreamInterceptor(grpcmiddleware.ChainStreamClient(c.streamIntercepts...)))

	if c.config.Scheme == "" || c.config.Authority == "" || c.config.APIEndpoint == "" {
		return nil, fmt.Errorf("rpc client dial: the scheme authority and api-endoint must set")
	}

	target := fmt.Sprintf("%v://%v/%v.%v", c.config.Scheme, c.config.Authority, scode, c.config.APIEndpoint)

	cc, err := grpc.DialContext(ctx, target, c.opts...)
	if err != nil {
		return nil, err
	}

	return cc, nil
}
