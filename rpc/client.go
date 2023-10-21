package rpc

import (
	"context"
	"fmt"

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
	if c.config.Scheme == "" || c.config.Authority == "" || c.config.APIEndpoint == "" {
		return nil, fmt.Errorf("rpc client dial: the scheme authority and api-endoint must set")
	}

	var all []grpc.DialOption
	// 各自定义 dial 的参数
	all = append(all, opts...)
	// 全局定义 dial 的参数
	all = append(all, c.opts...)
	// 全局定义的 unary 类型参数
	all = append(all, grpc.WithChainUnaryInterceptor(c.unaryIntercepts...))
	// 全局定义的 stream 类型参数
	all = append(all, grpc.WithChainStreamInterceptor(c.streamIntercepts...))

	target := fmt.Sprintf("%v://%v/%v.%v", c.config.Scheme, c.config.Authority, scode, c.config.APIEndpoint)

	cc, err := grpc.DialContext(ctx, target, all...)
	if err != nil {
		return nil, err
	}

	return cc, nil
}
