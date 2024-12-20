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
	"reflect"
	"strings"
	"time"

	grpcauth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	grpclogging "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	grpcrecovery "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	statusv1 "github.com/grpc-kit/pkg/api/known/status/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/rpc/interceptors/audit"
	"github.com/grpc-kit/pkg/vars"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
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

	// 配置 grpc-gateway 至 grpc 的连接选项
	var defaultOpts []grpc.DialOption
	creds, err := c.Services.getClientCredentials()
	if err != nil {
		panic(err)
	}
	defaultOpts = append(defaultOpts, grpc.WithTransportCredentials(creds))

	err = gw(ctx,
		rmux,
		fmt.Sprintf("%v:%v", forwardGWAddr, grpcListenPort),
		c.GetClientDialOption(defaultOpts...))

	return hmux, err
}

// getHTTPServeMux 获取通用的HTTP路由规则
func (c *LocalConfig) getHTTPServeMux(customOpts ...runtime.ServeMuxOption) (*http.ServeMux, *runtime.ServeMux) {
	// ServeMuxOption如果存在同样的设置选项，则以最后设置为准（见runtime.NewServeMux）
	defaultOpts := make([]runtime.ServeMuxOption, 0)

	// 根据 content-type 选择 marshal
	defaultOpts = append(defaultOpts, runtime.WithMarshalerOption(
		runtime.MIMEWildcard, &runtime.HTTPBodyMarshaler{
			Marshaler: &runtime.JSONPb{
				MarshalOptions:   c.Services.jsonMarshal,
				UnmarshalOptions: c.Services.jsonUnmarshal,
			},
		}))

	// 植入特定的请求头
	optionWithMetada := func(ctx context.Context, req *http.Request) metadata.MD {
		carrier := make(map[string]string)

		// 传递携带的信息，如获取并植入 traceparent 请求头
		otel.GetTextMapPropagator().Inject(ctx, propagation.MapCarrier(carrier))

		// 植入自定义请求头（全局请求ID）
		/*
			if val := req.Header.Get(HTTPHeaderRequestID); val != "" {
				carrier[HTTPHeaderRequestID] = val
			} else {
				carrier[HTTPHeaderRequestID] = c.Observables.calcRequestID(ctx)
				req.Header.Set(HTTPHeaderRequestID, carrier[HTTPHeaderRequestID])
			}
		*/

		md := metadata.New(carrier)

		// 植入认证鉴权信息
		ctx = c.Security.injectAuthHTTPHeader(ctx, req)
		if tmp, ok := metadata.FromIncomingContext(ctx); ok {
			md = metadata.Join(md, tmp)
		}

		// 传递 gateway 特定请求头至后端 grpc 服务端
		raddr := strings.Split(req.RemoteAddr, ":")
		if len(raddr) == 2 {
			md.Set("x-real-ip", raddr[0])
		}

		span := trace.SpanFromContext(ctx)
		if span == nil {
			return md
		}

		// 这里不可关闭，否则之后阶段通过 ctx 获取 span 将无法上报事件(span.IsRecording=flase)
		// defer span.End()

		if !c.Observables.hasRecordLogFieldsHTTPRequest() {
			return md
		}

		// 当 method=put 或 post 时，开启 http_request 记录且 content-type 为 json 时才记录 http.body
		if (req.Method == http.MethodPut || req.Method == http.MethodPost) &&
			strings.Contains(req.Header.Get("Content-Type"), "application/json") {

			rawBody, err := ioutil.ReadAll(req.Body)
			if err == nil {
				req.Body = ioutil.NopCloser(bytes.NewBuffer(rawBody))
				if len(rawBody) > 0 {
					span.AddEvent("http.request",
						trace.WithAttributes(attribute.String("http.request.body.data", string(rawBody))),
						trace.WithAttributes(attribute.Int("http.request.body.size", len(rawBody))),
					)
				}
			}
		}

		return md
	}

	// 正常响应时调用，统一植入特定内容
	forwardResponseOption := func(ctx context.Context, w http.ResponseWriter, msg proto.Message) error {
		// 禁用浏览器的 Content-Type 猜测行为
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// 限制仅可在相同域名页面的 frame 中展示
		w.Header().Set("X-Frame-Options", "sameorigin")
		// 防范 XSS 攻击，检测到攻击，浏览器将不会清除页面，而是阻止页面加载
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// 访问一个 HTTPS 网站，要求浏览器总是通过 HTTPS 访问它
		// w.Header().Set("Strict-Transport-Security", "max-age=172800")
		// 返回请求ID，如果存在 trace.id 的话，否则返回默认值
		w.Header().Set(HTTPHeaderRequestID, c.Observables.calcRequestID(ctx))

		// tracing 不可用或当前无法记录上报事件
		span := trace.SpanFromContext(ctx)
		if span == nil && !span.IsRecording() {
			return nil
		}
		span.SetStatus(otelcodes.Ok, codes.OK.String())

		// TODO；是否存在空值
		if msg == nil {
			return nil
		}

		// TODO; 成功处理时判断 proto 类型确认是否使用 204 状态码，是否有更好的实现方式
		// https://github.com/grpc-ecosystem/grpc-gateway/issues/240
		respType := reflect.TypeOf(msg)
		if respType.String() == "*emptypb.Empty" {
			w.WriteHeader(http.StatusNoContent)
			return nil
		}

		if c.Observables.hasRecordLogFieldsHTTPResponse() {
			// TODO; 如果msg是数组返回，则无法成功序列化为json
			respBody, err := protojson.Marshal(msg)
			if err != nil {
				return err
			}
			if len(respBody) > 2 {
				span.AddEvent("http.response",
					trace.WithAttributes(attribute.String("http.response.body.data", string(respBody))),
					trace.WithAttributes(attribute.Int("http.response.body.size", len(respBody))),
				)
			}
		}

		return nil
	}

	// 错误响应时调用，统一植入特定内容
	optionWithProtoErrorHandler := func(ctx context.Context, mux *runtime.ServeMux, _ runtime.Marshaler,
		w http.ResponseWriter, req *http.Request, err error) {
		s := errs.FromError(err)

		w.Header().Del("Trailer")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "sameorigin")
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// 请求的是忽略追踪的http url地址
		ignoreTracing := false
		span := trace.SpanFromContext(ctx)
		if span == nil {
			ignoreTracing = true
		} else {
			defer span.End()
		}

		// requestID := req.Header.Get(HTTPHeaderRequestID)
		requestID := c.Observables.calcRequestID(ctx)
		w.Header().Set(HTTPHeaderRequestID, requestID)

		if !ignoreTracing {
			// 传递携带的信息
			carrier := make(map[string]string)
			otel.GetTextMapPropagator().Inject(ctx, propagation.MapCarrier(carrier))
		}

		t := &statusv1.TracingRequest{Id: requestID}
		s = s.AppendDetail(t)

		body := &statusv1.ErrorResponse{
			Error: s.Status,
		}

		rawBody, err := protojson.Marshal(body)
		if err != nil {
			s = errs.Internal(ctx, t).WithMessage(err.Error())
			body.Error = s.Status
			rawBody, _ = protojson.Marshal(body)
		}

		// 接口请求错误情况下，均会记录响应体
		if !ignoreTracing {
			span.SetAttributes(
				attribute.KeyValue{
					Key:   "http.response.status_code",
					Value: attribute.IntValue(s.HTTPStatusCode()),
				},
			)

			switch s.HTTPStatusCode() {
			case http.StatusBadRequest:
				// 如果状态码是 400 则不认为错误
			case http.StatusNotFound:
				// 如果状态码是 404 则不认为错误
			case http.StatusNotImplemented:
				// 如果状态码是 501 则不认为错误
			default:
				span.RecordError(err, trace.WithStackTrace(false))

				// error.object
				// status_code status_message
				span.SetStatus(otelcodes.Error, s.GetStatus())

				span.AddEvent("http.response",
					trace.WithAttributes(attribute.String("http.response.body.data", string(rawBody))),
				)

				// TODO; 在错误情况下请求体已经在之前被读取过了，如何重置？
				// 当 method=put 或 post 时，开启 http_body 记录或开启 debug 模式与 content-type 为 json 时才记录 http.body
				if (req.Method == http.MethodPut || req.Method == http.MethodPost) &&
					strings.Contains(req.Header.Get("Content-Type"), "application/json") {

					reqBody, err := ioutil.ReadAll(req.Body)
					// c.logger.Infof("error found add body: %v, err: %v, remote addr: %v", string(reqBody), err, req.RemoteAddr)

					if err == nil {
						req.Body = ioutil.NopCloser(bytes.NewBuffer(reqBody))
						if len(reqBody) > 0 {
							span.AddEvent("http.request",
								trace.WithAttributes(attribute.String("http.request.body.data", string(reqBody))),
								trace.WithAttributes(attribute.Int("http.request.body.size", len(reqBody))),
							)
						}
					}
				}
			}
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
		if _, err := w.Write(rawBody); err != nil {
		}
	}

	defaultOpts = append(defaultOpts, runtime.WithMetadata(optionWithMetada))
	defaultOpts = append(defaultOpts, runtime.WithForwardResponseOption(forwardResponseOption))
	defaultOpts = append(defaultOpts, runtime.WithErrorHandler(optionWithProtoErrorHandler))
	defaultOpts = append(defaultOpts, customOpts...)
	rmux := runtime.NewServeMux(defaultOpts...)

	// TODO; 自定义 prometheus 指标

	hmux := http.NewServeMux()
	c.Observables.prometheusExporterHTTP(hmux)
	hmux.Handle("/ping", c.Security.addHTTPHandler(httpHandleHealthPing()))
	hmux.Handle("/version", c.Security.addHTTPHandler(httpHandleGetVersion()))

	if c.Debugger.EnablePprof {
		hmux.Handle("/debug/pprof/", c.Security.addHTTPHandlerFunc(pprof.Index))
		hmux.Handle("/debug/pprof/cmdline", c.Security.addHTTPHandlerFunc(pprof.Cmdline))
		hmux.Handle("/debug/pprof/profile", c.Security.addHTTPHandlerFunc(pprof.Profile))
		hmux.Handle("/debug/pprof/symbol", c.Security.addHTTPHandlerFunc(pprof.Symbol))
		hmux.Handle("/debug/pprof/trace", c.Security.addHTTPHandlerFunc(pprof.Trace))
	}

	handler := http.Handler(rmux)
	handler = c.Observables.addHTTPHandler(handler)

	// TODO；后续如需集成前端，可考虑添加 "/api" 前缀，把 ”/“ 存放静态 HTML
	// hmux.Handle("/", handler)
	hmux.Handle("/api/", handler)

	return hmux, rmux
}

// GetUnaryInterceptor 用于获取gRPC的一元拦截器
func (c *LocalConfig) GetUnaryInterceptor(interceptors ...grpc.UnaryServerInterceptor) grpc.ServerOption {
	// TODO; 移动到 observables 方法中

	var defaultUnaryOpt []grpc.UnaryServerInterceptor
	defaultUnaryOpt = append(defaultUnaryOpt,
		otelgrpc.UnaryServerInterceptor(
			otelgrpc.WithInterceptorFilter(c.Observables.grpcTracingEnableFilter),
		),
	)
	defaultUnaryOpt = append(defaultUnaryOpt,
		grpcauth.UnaryServerInterceptor(c.authValidate()),
	)

	// TODO; DEBUG; 审计拦截器
	if c.CloudEvents.hasAudit() {
		defaultUnaryOpt = append(defaultUnaryOpt,
			audit.UnaryServerInterceptor(
				audit.WithLogger(c.logger),
				audit.WithCloudEvent(c.CloudEvents.auditClient),
				audit.WithServiceName(c.GetServiceName()),
				audit.WithServiceCode(c.Services.ServiceCode),
				audit.WithMarshal(c.Services.jsonMarshal),
				audit.WithLevel(audit.LevelRequest),
			),
		)
	}

	defaultUnaryOpt = append(defaultUnaryOpt,
		grpclogging.UnaryServerInterceptor(c.interceptorLogger(c.logger),
			grpclogging.WithTimestampFormat(time.RFC3339Nano),
			grpclogging.WithLogOnEvents(grpclogging.FinishCall),
		))
	defaultUnaryOpt = append(defaultUnaryOpt,
		grpcrecovery.UnaryServerInterceptor(
			grpcrecovery.WithRecoveryHandlerContext(c.Observables.grpcPanicRecoveryHandler),
		),
	)
	defaultUnaryOpt = append(defaultUnaryOpt, interceptors...)

	return grpc.ChainUnaryInterceptor(defaultUnaryOpt...)
}

// GetStreamInterceptor xx
func (c *LocalConfig) GetStreamInterceptor(interceptors ...grpc.StreamServerInterceptor) grpc.ServerOption {
	/*
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
	*/

	// TODO; metrics
	/*
		srvMetrics := grpcprometheus.NewServerMetrics(
			grpcprometheus.WithServerHandlingTimeHistogram(
				grpcprometheus.WithHistogramBuckets([]float64{0.001, 0.01, 0.1, 0.3, 0.6, 1, 3, 6, 9, 20, 30, 60, 90, 120}),
			),
		)
	*/

	/*
		c.promRegistry.MustRegister(srvMetrics)
		exemplarFromContext := func(ctx context.Context) prometheus.Labels {
			if span := trace.SpanContextFromContext(ctx); span.IsSampled() {
				return prometheus.Labels{"traceID": span.TraceID().String()}
			}
			return nil
		}
	*/

	/*
		panicsTotal := promauto.With(c.promRegistry).NewCounter(prometheus.CounterOpts{
			Name: "grpc_req_panics_recovered_total",
			Help: "Total number of gRPC requests recovered from internal panic.",
		})
		grpcPanicRecoveryHandler := func(p any) (err error) {
			panicsTotal.Inc()
			// level.Error(rpcLogger).Log("msg", "recovered from panic", "panic", p, "stack", debug.Stack())
			return status.Errorf(codes.Internal, "%s", p)
		}
	*/

	var opts []grpc.StreamServerInterceptor
	opts = append(opts, otelgrpc.StreamServerInterceptor())
	// opts = append(opts, srvMetrics.StreamServerInterceptor())
	opts = append(opts, grpcrecovery.StreamServerInterceptor())
	opts = append(opts, grpcauth.StreamServerInterceptor(c.authValidate()))
	opts = append(opts, interceptors...)

	return grpc.ChainStreamInterceptor(opts...)
}

// GetClientDialOption 获取客户端连接的设置
func (c *LocalConfig) GetClientDialOption(customOpts ...grpc.DialOption) []grpc.DialOption {
	const grpcServiceConfig = `{"loadBalancingPolicy":"round_robin"}`
	var defaultOpts []grpc.DialOption
	defaultOpts = append(defaultOpts, grpc.WithDefaultServiceConfig(grpcServiceConfig))
	defaultOpts = append(defaultOpts, customOpts...)
	return defaultOpts
}

// GetClientUnaryInterceptor 获取客户端默认一元拦截器
func (c *LocalConfig) GetClientUnaryInterceptor() []grpc.UnaryClientInterceptor {
	/*
		// TODO; 根据fullMethodName进行过滤哪些需要记录payload的，返回false表示不记录
		logPayloadFilterFunc := func(ctx context.Context, fullMethodName string) bool {
			return false
		}

		// TODO; 根据fullMethodName进行过滤哪些需要记录请求状态的，返回false表示不记录
		logReqFilterOpts := []grpclogrus.Option{grpclogrus.WithDecider(func(fullMethodName string, err error) bool {
			// 忽略HealthCheck请求记录：msg="finished unary call with code OK" grpc.code=OK grpc.method=HealthCheck
			rpcName := path.Base(fullMethodName)
			switch rpcName {
			case "HealthCheck":
				return false
			case "Check", "Watch":
				return false
			default:
				return true
			}
		})}
	*/

	var opts []grpc.UnaryClientInterceptor
	opts = append(opts, otelgrpc.UnaryClientInterceptor())
	//opts = append(opts, grpcprometheus.UnaryClientInterceptor)
	// opts = append(opts, grpcopentracing.UnaryClientInterceptor())
	// opts = append(opts, grpclogrus.UnaryClientInterceptor(c.logger, logReqFilterOpts...))
	// opts = append(opts, grpclogrus.PayloadUnaryClientInterceptor(c.logger, logPayloadFilterFunc))
	return opts
}

// GetClientStreamInterceptor 获取客户端默认流拦截器
func (c *LocalConfig) GetClientStreamInterceptor() []grpc.StreamClientInterceptor {
	/*
		// TODO; 根据 fullMethodName 进行过滤哪些需要记录 payload 的，返回 false 表示不记录
		logPayloadFilterFunc := func(ctx context.Context, fullMethodName string) bool {
			return false
		}

		// TODO; 根据 fullMethodName 进行过滤哪些需要记录请求状态的，返回 false 表示不记录
		logReqFilterOpts := []grpclogrus.Option{grpclogrus.WithDecider(func(fullMethodName string, err error) bool {
			// 忽略HealthCheck请求记录：msg="finished unary call with code OK" grpc.code=OK grpc.method=HealthCheck
			return err == nil && path.Base(fullMethodName) != "HealthCheck"
		})}
	*/

	var opts []grpc.StreamClientInterceptor
	opts = append(opts, otelgrpc.StreamClientInterceptor())
	//opts = append(opts, grpcprometheus.StreamClientInterceptor)
	// opts = append(opts, grpcopentracing.StreamClientInterceptor())
	// opts = append(opts, grpclogrus.StreamClientInterceptor(c.logger, logReqFilterOpts...))
	// opts = append(opts, grpclogrus.PayloadStreamClientInterceptor(c.logger, logPayloadFilterFunc))
	return opts
}

// authValidate 认证与鉴权拦截器
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
				ctx = c.Security.withUsername(ctx, UsernameAnonymous)
				ctx = c.Security.withAuthenticationType(ctx, AuthenticationTypeNone)
				return ctx, nil
			}
		}

		// 如果未配置任何验证方式，则拒绝所有请求
		if c.Security.Authentication == nil {
			return ctx, errs.Unauthenticated(ctx).Err()
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
					return ctx, errs.Unauthenticated(ctx).Err()
				}

				for _, v := range c.Security.Authentication.HTTPUsers {
					if v.Username == tmps[0] && v.Password == tmps[1] {
						// 认证成功
						ctx = c.Security.withUsername(ctx, tmps[0])
						ctx = c.Security.withAuthenticationType(ctx, AuthenticationTypeBasic)
						ctx = c.Security.withGroups(ctx, v.Groups)

						if err := c.checkPermission(ctx, v.Groups); err != nil {
							return ctx, err
						}
						return ctx, nil
					}
				}
			}
		}

		// 说明存在bearer认证
		if c.Security.Authentication.OIDCProvider != nil {
			bearerToken, err := grpcauth.AuthFromMD(ctx, AuthenticationTypeBearer)
			if err != nil || bearerToken == "" {
				return ctx, errs.Unauthenticated(ctx).Err()
			}

			idToken, err := c.Security.verifyBearerToken(ctx, bearerToken)
			if err != nil {
				if idToken.Subject != "" || idToken.Email != "" {
					c.logger.Warnf("bearer token sub: %v email: %v verify err: %v", idToken.Subject, idToken.Email, err)
				} else {
					c.logger.Warnf("bearer token verify err: %v", err)
				}

				return ctx, errs.Unauthenticated(ctx).Err()
			}

			ctx = c.Security.withIDToken(ctx, idToken)
			ctx = c.Security.withUsername(ctx, idToken.Email)
			ctx = c.Security.withGroups(ctx, idToken.Groups)
			ctx = c.Security.withAuthenticationType(ctx, AuthenticationTypeBearer)

			if err := c.checkPermission(ctx, idToken.Groups); err != nil {
				return ctx, err
			}
			return ctx, nil
		}

		return ctx, errs.Unauthenticated(ctx).Err()
	}
}

func (c *LocalConfig) checkPermission(ctx context.Context, groups []string) error {
	// 需要当前用户组进行核对，是否拥护权限
	if len(c.Security.Authorization.AllowedGroups) > 0 {
		allow := false
		found := make(map[string]int, 0)
		for _, g := range c.Security.Authorization.AllowedGroups {
			found[g] = 0
		}
		for _, g := range groups {
			if _, ok := found[g]; ok {
				allow = true
				break
			}
		}
		if !allow {
			return errs.PermissionDenied(ctx).Err()
		}
	}

	// 基于 opa 项目进行鉴权
	allow, err := c.Security.policyAllow(ctx)
	if err != nil {
		c.logger.Errorf("check opa policy err: %v", err)
		return errs.PermissionDenied(ctx).Err()
	}
	if !allow {
		return errs.PermissionDenied(ctx).Err()
	}

	return nil
}

func httpHandleGetVersion() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		_, _ = io.WriteString(w, vars.GetVersion().String())
	}
}

func httpHandleHealthPing() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)

		_, _ = io.WriteString(w, "OK")
	}
}
