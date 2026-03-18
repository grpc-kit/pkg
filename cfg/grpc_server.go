package cfg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otelcodes "go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/errs"
	"github.com/grpc-kit/pkg/rpc/interceptors/audit"
	"github.com/grpc-kit/pkg/vars"
)

// registerGateway 注册 microservice.pb.gw
func (c *LocalConfig) registerGateway(ctx context.Context,
	gw func(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error,
	opts ...runtime.ServeMuxOption) (*http.ServeMux, error) {

	hmux, muxOpts := c.getHTTPServeMux(opts...)

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

	// TODO;
	apiMux := runtime.NewServeMux(muxOpts...)
	apiHandler := http.Handler(apiMux)
	apiHandler = c.Observables.addHTTPHandler(apiHandler)
	hmux.Handle("/api/", apiHandler)

	err = gw(ctx,
		apiMux,
		fmt.Sprintf("%v:%v", forwardGWAddr, grpcListenPort),
		c.GetClientDialOption(defaultOpts...))

	if c.Frontend.hasEnableAdmin() {
		adminMux := runtime.NewServeMux(muxOpts...)
		adminHandler := http.Handler(adminMux)
		adminHandler = c.Observables.addHTTPHandler(adminHandler)
		hmux.Handle("/builtin/admin/api/", adminHandler)

		err = adminv1.RegisterKnownAdminHandlerFromEndpoint(ctx,
			adminMux,
			fmt.Sprintf("%v:%v", forwardGWAddr, grpcListenPort),
			c.GetClientDialOption(defaultOpts...))
	}
	// TODO;

	return hmux, err
}

// getHTTPServeMux 获取通用的HTTP路由规则
func (c *LocalConfig) getHTTPServeMux(customOpts ...runtime.ServeMuxOption) (*http.ServeMux, []runtime.ServeMuxOption) {
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
		// 植入自定义 http 请求头
		c.setHTTPResponseHeaders(ctx, w)

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

		// 添加追踪信息
		s = s.AppendDetail(&errdetails.RequestInfo{
			RequestId: requestID,
			// ServingData: req.URL.String(),
		})
		// 之后考虑废弃移除使用以上结构代替
		// t := &statusv1.TracingRequest{Id: requestID}
		// s = s.AppendDetail(t)

		/*
			body := &statusv1.ErrorResponse{
				Error: s.Status,
			}

			rawBody, err := protojson.Marshal(body)
			if err != nil {
				s = errs.Internal(ctx).WithMessage(err.Error())
				body.Error = s.Status
				rawBody, _ = protojson.Marshal(body)
			}
		*/
		rawBody := s.ErrorResponseBody(ctx)

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

	/*
		optionWithStreamErrorHandler := func(context.Context, error) *status.Status {
			return status.New(codes.Internal, codes.Internal.String())
		}
	*/

	defaultOpts = append(defaultOpts, runtime.WithMetadata(optionWithMetada))
	defaultOpts = append(defaultOpts, runtime.WithForwardResponseOption(forwardResponseOption))
	defaultOpts = append(defaultOpts, runtime.WithErrorHandler(optionWithProtoErrorHandler))
	// defaultOpts = append(defaultOpts, runtime.WithStreamErrorHandler(optionWithStreamErrorHandler))
	defaultOpts = append(defaultOpts, customOpts...)

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

	return hmux, defaultOpts
}

// GetUnaryInterceptor 用于获取gRPC的一元拦截器
func (c *LocalConfig) GetUnaryInterceptor(interceptors ...grpc.UnaryServerInterceptor) grpc.ServerOption {
	// TODO; 移动到 observables 方法中

	var defaultOpts []grpc.UnaryServerInterceptor

	// TODO; 测试鉴权函数, begin
	/*
		rawBody, err := os.ReadFile("./examples/authz/rbac.json")
		if err != nil {
			panic("rbac read file err: " + err.Error())
		}
		si, err := authz.NewStatic(string(rawBody))
		if err != nil {
			panic("rbac new static err: " + err.Error())
		}
		defaultOpts = append(defaultOpts, si.UnaryInterceptor)
	*/
	// TODO; 测试鉴权函数, end

	defaultOpts = append(defaultOpts,
		grpcauth.UnaryServerInterceptor(c.authValidate()),
	)

	if c.CloudEvents.hasAuditEnabled() {
		auditLevel := c.CloudEvents.getAuditLevel()
		mustSucceed := c.CloudEvents.hasAuditEventMustSucceed()

		defaultOpts = append(defaultOpts,
			audit.UnaryServerInterceptor(
				audit.WithLogger(c.logger),
				audit.WithCloudEvent(c.CloudEvents.auditClient),
				audit.WithServiceName(c.GetServiceName()),
				audit.WithMarshal(c.Services.jsonMarshal),
				audit.WithLevel(auditLevel),
				audit.WithMustSucceed(mustSucceed),
			),
		)
	}

	defaultOpts = append(defaultOpts,
		grpclogging.UnaryServerInterceptor(c.interceptorLogger(c.logger),
			grpclogging.WithTimestampFormat(time.RFC3339Nano),
			grpclogging.WithLogOnEvents(grpclogging.FinishCall),
		),
	)

	defaultOpts = append(defaultOpts,
		grpcrecovery.UnaryServerInterceptor(
			grpcrecovery.WithRecoveryHandlerContext(c.Observables.grpcPanicRecoveryHandler),
		),
	)

	defaultOpts = append(defaultOpts, interceptors...)

	return grpc.ChainUnaryInterceptor(defaultOpts...)
}

// GetStreamInterceptor xx
func (c *LocalConfig) GetStreamInterceptor(interceptors ...grpc.StreamServerInterceptor) grpc.ServerOption {
	var defaultOpts []grpc.StreamServerInterceptor

	defaultOpts = append(defaultOpts,
		grpcauth.StreamServerInterceptor(c.authValidate()),
	)

	if c.CloudEvents.hasAuditEnabled() {
		auditLevel := c.CloudEvents.getAuditLevel()
		mustSucceed := c.CloudEvents.hasAuditEventMustSucceed()

		defaultOpts = append(defaultOpts,
			audit.StreamServerInterceptor(
				audit.WithLogger(c.logger),
				audit.WithCloudEvent(c.CloudEvents.auditClient),
				audit.WithServiceName(c.GetServiceName()),
				audit.WithMarshal(c.Services.jsonMarshal),
				audit.WithLevel(auditLevel),
				audit.WithMustSucceed(mustSucceed),
			),
		)
	}

	defaultOpts = append(defaultOpts,
		grpclogging.StreamServerInterceptor(c.interceptorLogger(c.logger),
			grpclogging.WithTimestampFormat(time.RFC3339Nano),
			grpclogging.WithLogOnEvents(grpclogging.FinishCall),
		),
	)

	defaultOpts = append(defaultOpts,
		grpcrecovery.StreamServerInterceptor(
			grpcrecovery.WithRecoveryHandlerContext(c.Observables.grpcPanicRecoveryHandler),
		),
	)

	defaultOpts = append(defaultOpts, interceptors...)

	return grpc.ChainStreamInterceptor(defaultOpts...)
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
	// opts = append(opts, otelgrpc.UnaryClientInterceptor())
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

		// /grpc_kit.api.known.admin.v1.KnownAdmin/CreateAuthLogin
		// 确认是否为全局已知跳过认证的 rpc 方法
		switch currentMethod {
		case "/grpc_kit.api.known.admin.v1.KnownAdmin/ListAuthProviders",
			"/grpc_kit.api.known.admin.v1.KnownAdmin/CreateAuthLogin",
			"/grpc_kit.api.known.admin.v1.KnownAdmin/VerifyAuthMFA",
			"/grpc_kit.api.known.admin.v1.KnownAdmin/StartAuthMFASetup",
			"/grpc_kit.api.known.admin.v1.KnownAdmin/ConfirmAuthMFASetup",
			"/grpc_kit.api.known.admin.v1.KnownAdmin/CreateAuthToken",
			"/grpc_kit.api.known.admin.v1.KnownAdmin/GetAuthCallback",
			"/grpc_kit.api.known.admin.v1.KnownAdmin/GetOAuth2Discovery",
			"/grpc_kit.api.known.admin.v1.KnownAdmin/GetOAuth2JSONWebKeys":
			ctx = c.Security.withUserID(ctx, 0)
			ctx = c.Security.withUsername(ctx, UsernameAnonymous)
			ctx = c.Security.withAuthenticationType(ctx, AuthenticationTypeNone)
			return ctx, nil
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
					if v.Username == tmps[0] {
						h := sha256.New()
						h.Write([]byte(tmps[1]))
						userHash := hex.EncodeToString(h.Sum(nil))

						if v.Password == tmps[1] || v.PasswordHash == userHash {
							// 认证成功
							ctx = c.Security.withUserID(ctx, v.UserID)
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
			ctx = c.Security.withUserID(ctx, idToken.GetMustUserID())
			ctx = c.Security.withUsername(ctx, idToken.Username)
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

func (c *LocalConfig) setHTTPResponseHeaders(ctx context.Context, w http.ResponseWriter) {
	md, ok := runtime.ServerMetadataFromContext(ctx)
	if ok {
		for k, v := range md.HeaderMD {
			// 必须以 "X-" 开头
			if !strings.HasPrefix(strings.ToUpper(k), "X-") {
				continue
			}

			for i := range v {
				w.Header().Add(k, v[i])
			}
		}
		for k, v := range md.TrailerMD {
			// 必须以 "X-" 开头
			if !strings.HasPrefix(strings.ToUpper(k), "X-") {
				continue
			}

			for i := range v {
				w.Header().Add(k, v[i])
			}
		}
	}

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
		// TODO; 检测已开启服务的连接是否正常

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)

		_, _ = io.WriteString(w, "OK")
	}
}
