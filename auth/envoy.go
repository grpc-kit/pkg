package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/open-policy-agent/opa/util"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// authMetadataPrefix 用于在框架中传递元数据头前缀
	authMetadataPrefix = "grpc-kit-"
)

type envoyProxy struct {
}

// extractHTTPHeader 提取 http 请求头转换为 grpc 元数据
func (e *envoyProxy) extractHTTPHeader(ctx context.Context, req *http.Request) metadata.MD {
	h := make(map[string]string)

	h[fmt.Sprintf("%vhost", authMetadataPrefix)] = req.Host
	h[fmt.Sprintf("%vmethod", authMetadataPrefix)] = req.Method
	h[fmt.Sprintf("%vrequest-uri", authMetadataPrefix)] = req.RequestURI
	h[fmt.Sprintf("%vproto", authMetadataPrefix)] = req.Proto
	h[fmt.Sprintf("%vremote-addr", authMetadataPrefix)] = req.RemoteAddr

	if req.TLS == nil {
		h[fmt.Sprintf("%vscheme", authMetadataPrefix)] = "http"
	} else {
		h[fmt.Sprintf("%vscheme", authMetadataPrefix)] = "https"
	}

	return metadata.New(h)
}

// getCheckRequest 对用户输入数据转换为兼容 envoy 请求验证的数据格式
// https://pkg.go.dev/github.com/envoyproxy/go-control-plane@v0.12.0/envoy/service/auth/v3#CheckRequest
func (e *envoyProxy) getCheckRequest(ctx context.Context) (*authv3.CheckRequest, error) {
	input := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Time: timestamppb.New(time.Now()),
				Http: &authv3.AttributeContext_HttpRequest{
					Headers: map[string]string{},
					// Method: "GET",
					// 请求目标，即出现在 HTTP 请求的第一行中的内容，包括 URL 路径和查询字符串。不执行解码操作
					// Path: "/",
				},
			},
			MetadataContext: &corev3.Metadata{},
		},
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		for k, v := range md {
			switch k {
			case "x-tr-request-id", "x-request-id":
				input.Attributes.Request.Http.Id = v[0]
			case fmt.Sprintf("%v%v", authMetadataPrefix, "scheme"):
				input.Attributes.Request.Http.Scheme = v[0]
				input.Attributes.Request.Http.Headers[":scheme"] = v[0]
			case fmt.Sprintf("%v%v", authMetadataPrefix, "host"):
				input.Attributes.Request.Http.Host = v[0]
				input.Attributes.Request.Http.Headers[":authority"] = v[0]
			case fmt.Sprintf("%v%v", authMetadataPrefix, "method"):
				input.Attributes.Request.Http.Headers[":method"] = strings.ToUpper(v[0])
				input.Attributes.Request.Http.Method = strings.ToUpper(v[0])
			case fmt.Sprintf("%v%v", authMetadataPrefix, "request-uri"):
				input.Attributes.Request.Http.Path = v[0]
				input.Attributes.Request.Http.Headers[":path"] = v[0]
			case fmt.Sprintf("%v%v", authMetadataPrefix, "proto"):
				input.Attributes.Request.Http.Protocol = v[0]
			case fmt.Sprintf("%v%v", authMetadataPrefix, "remote-addr"):
				addr := strings.Split(v[0], ":")
				if len(addr) != 2 {
					continue
				}
				port, err := strconv.Atoi(addr[1])
				if err != nil {
					continue
				}

				input.Attributes.Source = &authv3.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{
								Address: addr[0],
								PortSpecifier: &corev3.SocketAddress_PortValue{
									PortValue: uint32(port),
								},
							},
						},
					},
				}
			case ":authority":
				// 如果来自 grpc-gateway 的请求，则忽略
				// 127.0.0.1:10081
				// ignore
			case "user-agent":
			// 如果来自 grpc-gateway 的请求，则忽略
			// grpc-go/1.63.2
			// ignore
			case "content-type":
				// application/grpc
			default:
				if strings.HasPrefix(k, runtime.MetadataPrefix) {
					tmpHeader := strings.Replace(k, runtime.MetadataPrefix, "", 1)
					input.Attributes.Request.Http.Headers[tmpHeader] = strings.Join(v, ",")
				} else {
					input.Attributes.Request.Http.Headers[k] = strings.Join(v, ",")
				}
			}
		}
	}

	return input, nil
}

// requestToInput envoy CheckReuqest 结构体二次分析添加额外属性，以便同 "opa-envoy-plugin" 插件
// https://github.com/open-policy-agent/opa-envoy-plugin/blob/main/envoyauth/request.go
func (e *envoyProxy) requestToInput(req *authv3.CheckRequest) (map[string]interface{}, error) {
	input := make(map[string]interface{}, 0)

	input["version"] = map[string]string{"ext_authz": "v3", "encoding": "protojson"}

	bs, err := protojson.Marshal(req)
	if err != nil {
		return input, err
	}

	err = util.UnmarshalJSON(bs, &input)
	if err != nil {
		return nil, err
	}

	reqPath := req.GetAttributes().GetRequest().GetHttp().GetPath()
	parsedPath, parsedQuery, err := e.getParsedPathAndQuery(reqPath)
	if err != nil {
		return nil, err
	}

	input["parsed_path"] = parsedPath
	input["parsed_query"] = parsedQuery

	return input, nil
}

func (e *envoyProxy) getParsedPathAndQuery(path string) ([]interface{}, map[string]interface{}, error) {
	parsedURL, err := url.Parse(path)
	if err != nil {
		return nil, nil, err
	}

	parsedPath := strings.Split(strings.TrimLeft(parsedURL.Path, "/"), "/")
	parsedPathInterface := make([]interface{}, len(parsedPath))
	for i, v := range parsedPath {
		parsedPathInterface[i] = v
	}

	parsedQueryInterface := make(map[string]interface{})
	for paramKey, paramValues := range parsedURL.Query() {
		queryValues := make([]interface{}, len(paramValues))
		for i, v := range paramValues {
			queryValues[i] = v
		}
		parsedQueryInterface[paramKey] = queryValues
	}

	return parsedPathInterface, parsedQueryInterface, nil
}
