package rpc

import (
	"context"
	"net"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc/metadata"
)

// ClientSourceIPs 用于获取当前请求的源 IP 列表，即 x-forwarded-for 头
func ClientSourceIPs(ctx context.Context) []string {
	result := make([]string, 0)

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return result
	}

	if xffs := md.Get("x-forwarded-for"); len(xffs) > 0 {
		// 如果存在多个头，则仅取第一个
		xffList := strings.Split(xffs[0], ",")

		if len(xffList) > 0 {
			for _, xff := range xffList {
				xff = strings.TrimSpace(xff)
				if net.ParseIP(xff) != nil {
					result = append(result, xff)
				}
			}
		}
	}

	return result
}

// ClientUserAgent 用于获取当前请求的 User-Agent
func ClientUserAgent(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	headerName := "user-agent"
	if tmp := md.Get(runtime.MetadataPrefix + headerName); len(tmp) > 0 {
		return tmp[0]
	}

	if tmp := md.Get(headerName); len(tmp) > 0 {
		return tmp[0]
	}

	return ""
}

// ClientRealIP 用于获取当前请求源 IP 地址，既 x-real-ip 或 x-forwarded-for 头
func ClientRealIP(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	if realIPs := md.Get("x-real-ip"); len(realIPs) > 0 {
		return realIPs[0]
	}

	xff := ClientSourceIPs(ctx)
	if len(xff) > 0 {
		return xff[0]
	}

	return ""
}
