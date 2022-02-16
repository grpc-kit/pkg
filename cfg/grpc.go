package cfg

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/pprof"
	"net/textproto"
	"path"
	"strings"

	"github.com/gogo/gateway"
	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/google/uuid"
	grpcmiddleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpcauth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpclogrus "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpcrecovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	grpcopentracing "github.com/grpc-ecosystem/go-grpc-middleware/tracing/opentracing"
	grpcprometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	api "github.com/grpc-kit/api/proto/v1"
	"github.com/grpc-kit/pkg/errors"
	"github.com/grpc-kit/pkg/version"
	"github.com/opentracing-contrib/go-stdlib/nethttp"
	opentracing "github.com/opentracing/opentracing-go"
	opentracinglog "github.com/opentracing/opentracing-go/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/metadata"
)

// registerGateway 注册 microservice.pb.gw
func (c *LocalConfig) registerGateway(ctx context.Context,
	gw func(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error,
	opts ...runtime.ServeMuxOption) (*http.ServeMux, error) {

	hmux, rmux := c.getHTTPServeMux(opts...)

	var forwardGWAddr string
	grpcListenAddr, grpcListenPort, err := c.Services.getGRPCListenHostPort()
	if err != nil {
		return hmux, err
	}

	if grpcListenAddr == "0.0.0.0" || grpcListenAddr == "127.0.0.1" {
		forwardGWAddr = "127.0.0.1"
	} else {
		forwardGWAddr = grpcListenAddr
	}

	err = gw(ctx,
		rmux,
		fmt.Sprintf("%v:%v", forwardGWAddr, grpcListenPort),
		c.GetClientDialOption())

	return hmux, err
}

// getHTTPServeMux 获取通用的HTTP路由规则
func (c *LocalConfig) getHTTPServeMux(customOpts ...runtime.ServeMuxOption) (*http.ServeMux, *runtime.ServeMux) {
	// ServeMuxOption如果存在同样的设置选项，则以最后设置为准（见runtime.NewServeMux）
	defaultOpts := make([]runtime.ServeMuxOption, 0)

	// 根据content-type选择marshal
	// jsonpb使用gogo版本，代替golang/protobuf/jsonpb
	defaultOpts = append(defaultOpts, runtime.WithMarshalerOption(
		runtime.MIMEWildcard, &gateway.JSONPb{OrigName: true, EmitDefaults: true}))

	// 植入特定的请求头
	optionWithMetada := func(ctx context.Context, req *http.Request) metadata.MD {
		carrier := make(map[string]string)
		// 植入自定义请求头（全局请求ID）
		if val := req.Header.Get(HTTPHeaderRequestID); val != "" {
			carrier[HTTPHeaderRequestID] = val
		} else {
			carrier[HTTPHeaderRequestID] = calcRequestID(carrier)
			req.Header.Set(HTTPHeaderRequestID, carrier[HTTPHeaderRequestID])
		}

		span := opentracing.SpanFromContext(ctx)
		if span == nil {
			return metadata.New(carrier)
		}
		if err := span.Tracer().Inject(
			span.Context(),
			opentracing.TextMap,
			opentracing.TextMapCarrier(carrier),
		); err != nil {
			return metadata.New(carrier)
		}
		span.SetTag("request.id", carrier[HTTPHeaderRequestID])

		// 当method=put或post时，开启http_body记录或开启debug模式与content-type为json时才记录http.body
		if (c.Opentracing.LogFields.HTTPBody || c.Debugger.LogLevel == "debug") &&
			(req.Method == http.MethodPut || req.Method == http.MethodPost) &&
			strings.Contains(req.Header.Get("Content-Type"), "application/json") {

			rawBody, err := ioutil.ReadAll(req.Body)
			if err == nil {
				req.Body = ioutil.NopCloser(bytes.NewBuffer(rawBody))
				if len(rawBody) > 0 {
					span.LogFields(opentracinglog.String("http.body", string(rawBody)))
				}
			}
		}

		return metadata.New(carrier)
	}

	// 正常响应时调用，统一植入特定内容
	forwardResponseOption := func(ctx context.Context, w http.ResponseWriter, msg proto.Message) error {
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// TODO; 如果msg是数组返回，则无法成功序列化为json
		if c.Opentracing.LogFields.HTTPResponse {
			span := opentracing.SpanFromContext(ctx)
			if span == nil {
				return nil
			}

			var buf bytes.Buffer
			x := jsonpb.Marshaler{}
			if err := x.Marshal(&buf, msg); err != nil {
			}
			respBody := buf.String()
			if len(respBody) <= 2 {
				respBody = msg.String()
			}
			span.LogFields(opentracinglog.String("http.body", respBody))
		}

		return nil
	}

	// 错误响应时调用，统一植入特定内容
	optionWithProtoErrorHandler := func(ctx context.Context, mux *runtime.ServeMux, _ runtime.Marshaler,
		w http.ResponseWriter, req *http.Request, err error) {
		s := errors.FromError(err)

		w.Header().Del("Trailer")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// 请求的是忽略追踪的http url地址
		ignoreTracing := false
		span := opentracing.SpanFromContext(ctx)
		if span == nil {
			ignoreTracing = true
		}

		requestID := req.Header.Get(HTTPHeaderRequestID)
		if requestID != "" {
			w.Header().Set(HTTPHeaderRequestID, requestID)
		} else {
			carrier := make(map[string]string)
			if !ignoreTracing {
				span.Tracer().Inject(
					span.Context(),
					opentracing.TextMap,
					opentracing.TextMapCarrier(carrier))
			}
			requestID = calcRequestID(carrier)
		}

		t := &api.TracingRequest{Id: requestID}
		s = s.AppendDetail(t)

		body := &errors.Response{
			Error: *s,
		}

		// 错误返回均使用golang/protobuf/jsonpb进行序列，忽略marshaler
		x := jsonpb.Marshaler{}
		var buf bytes.Buffer
		if err := x.Marshal(&buf, body); err != nil {
			s = errors.Internal(ctx, t).WithMessage(err.Error())
			body.Error = *s
			x.Marshal(&buf, body)
		}

		// 接口请求错误情况下，均会记录响应体
		if !ignoreTracing {
			span.SetTag("request.id", requestID)
			rawBody, err := ioutil.ReadAll(req.Body)
			if err == nil {
				if len(rawBody) > 0 {
					span.LogFields(opentracinglog.String("http.body", string(rawBody)))
				}
			}
			span.LogFields(opentracinglog.String("http.response", buf.String()))
		}

		md, ok := runtime.ServerMetadataFromContext(ctx)
		if ok {
			for k := range md.TrailerMD {
				tKey := textproto.CanonicalMIMEHeaderKey(fmt.Sprintf("%s%s", runtime.MetadataTrailerPrefix, k))
				w.Header().Add("Trailer", tKey)
			}
			for k, vs := range md.TrailerMD {
				tKey := fmt.Sprintf("%s%s", runtime.MetadataTrailerPrefix, k)
				for _, v := range vs {
					w.Header().Add(tKey, v)
				}
			}
		}

		w.WriteHeader(s.HTTPStatusCode())
		if _, err := w.Write(buf.Bytes()); err != nil {
		}
	}

	defaultOpts = append(defaultOpts, runtime.WithMetadata(optionWithMetada))
	defaultOpts = append(defaultOpts, runtime.WithForwardResponseOption(forwardResponseOption))
	defaultOpts = append(defaultOpts, runtime.WithProtoErrorHandler(optionWithProtoErrorHandler))
	defaultOpts = append(defaultOpts, customOpts...)
	rmux := runtime.NewServeMux(defaultOpts...)

	hmux := http.NewServeMux()
	hmux.Handle("/metrics", promhttp.Handler())
	hmux.Handle("/version", httpHandleGetVersion())

	if c.Debugger.EnablePprof {
		hmux.HandleFunc("/debug/pprof/", pprof.Index)
		hmux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		hmux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		hmux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		hmux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	hmux.Handle("/", nethttp.Middleware(
		opentracing.GlobalTracer(),
		rmux,
		// 定义http下component名称
		nethttp.MWComponentName("grpc-gateway"),
		// 返回false，则不会进行追踪
		nethttp.MWSpanFilter(func(r *http.Request) bool {
			switch r.URL.Path {
			case "/healthz", "/version", "/metrics", "/favicon.ico":
				// 忽略这几个http请求的链路追踪
				return false
			}
			return true
		}),
		// 定义http追踪的方法名称
		nethttp.OperationNameFunc(func(r *http.Request) string {
			return fmt.Sprintf("http %s %s", strings.ToLower(r.Method), r.URL.Path)
		}),
	))

	return hmux, rmux
}

// GetUnaryInterceptor 用于获取gRPC的一元拦截器
func (c *LocalConfig) GetUnaryInterceptor(interceptors ...grpc.UnaryServerInterceptor) grpc.ServerOption {
	// TODO; 根据fullMethodName进行过滤哪些需要记录gRPC调用链，返回false表示不记录
	tracingFilterFunc := grpcopentracing.WithFilterFunc(func(ctx context.Context, fullMethodName string) bool {
		return path.Base(fullMethodName) != "HealthCheck"
	})

	// TODO; 根据fullMethodName进行过滤哪些需要记录payload的，返回false表示不记录
	logPayloadFilterFunc := func(ctx context.Context, fullMethodName string, servingObject interface{}) bool {
		return false
	}

	// TODO; 根据fullMethodName进行过滤哪些需要记录请求状态的，返回false表示不记录
	logReqFilterOpts := []grpclogrus.Option{grpclogrus.WithDecider(func(fullMethodName string, err error) bool {
		// 忽略HealthCheck请求记录：msg="finished unary call with code OK" grpc.code=OK grpc.method=HealthCheck
		return err == nil && path.Base(fullMethodName) != "HealthCheck"
	})}

	var defaultUnaryOpt []grpc.UnaryServerInterceptor
	defaultUnaryOpt = append(defaultUnaryOpt, grpcprometheus.UnaryServerInterceptor)
	defaultUnaryOpt = append(defaultUnaryOpt, grpcrecovery.UnaryServerInterceptor())
	defaultUnaryOpt = append(defaultUnaryOpt, grpcauth.UnaryServerInterceptor(c.authValidate()))
	defaultUnaryOpt = append(defaultUnaryOpt, grpcopentracing.UnaryServerInterceptor(tracingFilterFunc))
	defaultUnaryOpt = append(defaultUnaryOpt, grpclogrus.UnaryServerInterceptor(c.logger, logReqFilterOpts...))
	defaultUnaryOpt = append(defaultUnaryOpt, grpclogrus.PayloadUnaryServerInterceptor(c.logger, logPayloadFilterFunc))
	defaultUnaryOpt = append(defaultUnaryOpt, interceptors...)

	return grpc.UnaryInterceptor(grpcmiddleware.ChainUnaryServer(defaultUnaryOpt...))
}

// GetStreamInterceptor xx
func (c *LocalConfig) GetStreamInterceptor(interceptors ...grpc.StreamServerInterceptor) grpc.ServerOption {
	// TODO; 根据fullMethodName进行过滤哪些需要记录gRPC调用链，返回false表示不记录
	tracingFilterFunc := grpcopentracing.WithFilterFunc(func(ctx context.Context, fullMethodName string) bool {
		return path.Base(fullMethodName) != "HealthCheck"
	})

	// TODO; 根据fullMethodName进行过滤哪些需要记录payload的，返回false表示不记录
	logPayloadFilterFunc := func(ctx context.Context, fullMethodName string, servingObject interface{}) bool {
		return false
	}

	// TODO; 根据fullMethodName进行过滤哪些需要记录请求状态的，返回false表示不记录
	logReqFilterOpts := []grpclogrus.Option{grpclogrus.WithDecider(func(fullMethodName string, err error) bool {
		// 忽略HealthCheck请求记录：msg="finished unary call with code OK" grpc.code=OK grpc.method=HealthCheck
		return err == nil && path.Base(fullMethodName) != "HealthCheck"
	})}

	var opts []grpc.StreamServerInterceptor
	opts = append(opts, grpcprometheus.StreamServerInterceptor)
	opts = append(opts, grpcrecovery.StreamServerInterceptor())
	opts = append(opts, grpcauth.StreamServerInterceptor(c.authValidate()))
	opts = append(opts, grpcopentracing.StreamServerInterceptor(tracingFilterFunc))
	opts = append(opts, grpclogrus.StreamServerInterceptor(c.logger, logReqFilterOpts...))
	opts = append(opts, grpclogrus.PayloadStreamServerInterceptor(c.logger, logPayloadFilterFunc))
	opts = append(opts, interceptors...)

	return grpc.StreamInterceptor(grpcmiddleware.ChainStreamServer(opts...))
}

// GetClientDialOption 获取客户端连接的设置
func (c *LocalConfig) GetClientDialOption(customOpts ...grpc.DialOption) []grpc.DialOption {
	var defaultOpts []grpc.DialOption
	defaultOpts = append(defaultOpts, grpc.WithInsecure())
	defaultOpts = append(defaultOpts, grpc.WithBalancerName(roundrobin.Name))
	defaultOpts = append(defaultOpts, customOpts...)
	return defaultOpts
}

// GetClientUnaryInterceptor 获取客户端默认一元拦截器
func (c *LocalConfig) GetClientUnaryInterceptor() []grpc.UnaryClientInterceptor {
	// TODO; 根据fullMethodName进行过滤哪些需要记录payload的，返回false表示不记录
	logPayloadFilterFunc := func(ctx context.Context, fullMethodName string) bool {
		return false
	}

	// TODO; 根据fullMethodName进行过滤哪些需要记录请求状态的，返回false表示不记录
	logReqFilterOpts := []grpclogrus.Option{grpclogrus.WithDecider(func(fullMethodName string, err error) bool {
		// 忽略HealthCheck请求记录：msg="finished unary call with code OK" grpc.code=OK grpc.method=HealthCheck
		return err == nil && path.Base(fullMethodName) != "HealthCheck"
	})}

	var opts []grpc.UnaryClientInterceptor
	opts = append(opts, grpcprometheus.UnaryClientInterceptor)
	opts = append(opts, grpcopentracing.UnaryClientInterceptor())
	opts = append(opts, grpclogrus.UnaryClientInterceptor(c.logger, logReqFilterOpts...))
	opts = append(opts, grpclogrus.PayloadUnaryClientInterceptor(c.logger, logPayloadFilterFunc))
	return opts
}

// GetClientStreamInterceptor 获取客户端默认流拦截器
func (c *LocalConfig) GetClientStreamInterceptor() []grpc.StreamClientInterceptor {
	// TODO; 根据fullMethodName进行过滤哪些需要记录payload的，返回false表示不记录
	logPayloadFilterFunc := func(ctx context.Context, fullMethodName string) bool {
		return false
	}

	// TODO; 根据fullMethodName进行过滤哪些需要记录请求状态的，返回false表示不记录
	logReqFilterOpts := []grpclogrus.Option{grpclogrus.WithDecider(func(fullMethodName string, err error) bool {
		// 忽略HealthCheck请求记录：msg="finished unary call with code OK" grpc.code=OK grpc.method=HealthCheck
		return err == nil && path.Base(fullMethodName) != "HealthCheck"
	})}

	var opts []grpc.StreamClientInterceptor
	opts = append(opts, grpcprometheus.StreamClientInterceptor)
	opts = append(opts, grpcopentracing.StreamClientInterceptor())
	opts = append(opts, grpclogrus.StreamClientInterceptor(c.logger, logReqFilterOpts...))
	opts = append(opts, grpclogrus.PayloadStreamClientInterceptor(c.logger, logPayloadFilterFunc))
	return opts
}

// authValidate 实现认证，待实现鉴权
func (c *LocalConfig) authValidate() grpcauth.AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		// 如果存在认证请求头，同时帮忙传递下去
		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			authToken, found := md["authorization"]
			if found {
				for _, token := range authToken {
					ctx = metadata.AppendToOutgoingContext(ctx, "authorization", token)
				}
			}
		}

		// 是否开启认证鉴权
		if !c.Security.Enable {
			return ctx, nil
		}

		// 是否允许不安全的RPC调用
		// TODO；针对这类rpc在接口认证就无法获取user信息
		var currentRPC string
		currentMethod, ok := grpc.Method(ctx)
		if ok {
			currentRPC = path.Base(currentMethod)
		}
		for _, rpc := range c.Security.Authentication.InsecureRPCs {
			if currentRPC == rpc {
				ctx = c.WithUsername(ctx, UsernameAnonymous)
				ctx = c.WithAuthenticationType(ctx, AuthenticationTypeNone)
				return ctx, nil
			}
		}

		// 如果未配置任何验证方式，则拒绝所有请求
		if c.Security.Authentication == nil {
			return ctx, errors.Unauthenticated(ctx).Err()
		}

		// 验证http basic认证
		if len(c.Security.Authentication.HTTPUsers) > 0 {
			basicToken, err := grpcauth.AuthFromMD(ctx, AuthenticationTypeBasic)
			if err == nil && basicToken != "" {
				payload, err := base64.StdEncoding.DecodeString(basicToken)
				if err != nil {
					return ctx, err
				}

				tmps := strings.Split(string(payload), ":")
				if len(tmps) != 2 {
					return ctx, errors.Unauthenticated(ctx).Err()
				}

				for _, v := range c.Security.Authentication.HTTPUsers {
					if v.Username == tmps[0] && v.Password == tmps[1] {
						// 认证成功
						ctx = c.WithUsername(ctx, tmps[0])
						ctx = c.WithAuthenticationType(ctx, AuthenticationTypeBasic)
						return ctx, nil
					}
				}
			}
		}

		// 说明存在bearer认证
		if c.Security.Authentication.OIDCProvider != nil {
			bearerToken, err := grpcauth.AuthFromMD(ctx, AuthenticationTypeBearer)
			if err != nil || bearerToken == "" {
				return ctx, errors.Unauthenticated(ctx).Err()
			}

			tokenVerifier, ok := c.Security.idTokenVerifier()
			if !ok {
				return ctx, errors.Unauthenticated(ctx).WithMessage(err.Error()).Err()
			}

			idToken, err := tokenVerifier.Verify(ctx, bearerToken)
			if err != nil {
				return ctx, errors.Unauthenticated(ctx).WithMessage(err.Error()).Err()
			}

			var temp IDTokenClaims
			if err := idToken.Claims(&temp); err != nil {
				return ctx, errors.Unauthenticated(ctx).WithMessage(err.Error()).Err()
			}

			ctx = c.WithIDToken(ctx, temp)
			ctx = c.WithUsername(ctx, temp.Email)
			ctx = c.WithAuthenticationType(ctx, AuthenticationTypeBearer)

			return ctx, nil
		}

		return ctx, errors.Unauthenticated(ctx).Err()
	}
}

func calcRequestID(carrier map[string]string) string {
	requestID := "0123456789abcdef0123456789abcdef"

	tch, ok := carrier[TraceContextHeaderName]
	if ok {
		tmps := strings.Split(tch, ":")
		if len(tmps) >= 2 {
			requestID = fmt.Sprintf("%v%v", tmps[0], tmps[1])
		}
	} else {
		requestID = strings.Replace(uuid.New().String(), "-", "", -1)
	}

	return requestID
}

func httpHandleGetVersion() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		_, _ = io.WriteString(w, version.Get().String())
	}
}
