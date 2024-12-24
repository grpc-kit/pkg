package audit

import (
	"context"
	"strings"

	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/grpc-kit/pkg/errs"
	"google.golang.org/grpc"
)

// UnaryServerInterceptor 审计事件 grpc unary 拦截器
func UnaryServerInterceptor(opts ...Option) grpc.UnaryServerInterceptor {
	opt := defaultOption

	for _, o := range opts {
		o(opt)
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if opt.level == LevelNone {
			return handler(ctx, req)
		}

		// "/default.api.oneops.netdev.v1.OneopsNetdev/DisplaySwitchPortVlans"
		parts := strings.Split(info.FullMethod, "/")
		if len(parts) < 3 {
			opt.logger.Warnf("failed to parse grpc metho: %s, ignore audit", info.FullMethod)
			return handler(ctx, req)
		}

		grpcService := parts[1]
		grpcMethod := parts[2]

		// TODO；针对特殊的 method 不做审计
		switch grpcMethod {
		case "HealthCheck":
			return handler(ctx, req)
		}

		ce := event.New()
		ce.SetSpecVersion(event.CloudEventsVersionV1)
		ce.SetSource(opt.serviceName)
		ce.SetType("internal.audit")
		ce.SetSubject(grpcMethod)

		ed := opt.createEventData(ctx)
		ed.GRPCMethod = grpcMethod
		ed.GRPCService = grpcService

		// 记录请求体
		if opt.level == LevelRequest || opt.level == LevelRequestResponse {
			jsonData, ok, jsonErr := opt.marshalJson(req)
			if jsonErr == nil && ok {
				ed.setRequestObject(jsonData)
			}
		}

		if err := opt.sendAuditEvent(ctx, ce, ed); err != nil {
			// TODO; 植入性能指标

			return nil, errs.Unavailable(ctx).WithMessage(err.Error())
		}

		resp, err := handler(ctx, req)

		// 记录响应体审计阶段
		if opt.level == LevelRequestResponse {
			// TODO; 避免 err 变量污染

			ed.setResponseStatus(err)

			if err != nil {
				jsonData, ok, jsonErr := opt.marshalJson(err)
				if jsonErr == nil && ok {
					ed.setResponseObject(jsonData)
				}
			} else {
				jsonData, ok, jsonErr := opt.marshalJson(resp)
				if jsonErr == nil && ok {
					ed.setResponseObject(jsonData)
				}
			}

			if sendErr := opt.sendAuditEvent(ctx, ce, ed); sendErr != nil {
				// TODO; 植入性能指标

				return nil, errs.Unavailable(ctx).WithMessage(err.Error())
			}
		}

		return resp, err
	}
}
