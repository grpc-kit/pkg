package audit

import (
	"context"

	"google.golang.org/grpc"

	"github.com/grpc-kit/pkg/errs"
)

// UnaryServerInterceptor 审计事件 grpc unary 拦截器
func UnaryServerInterceptor(opts ...Option) grpc.UnaryServerInterceptor {
	opt := defaultOption

	for _, o := range opts {
		o(opt)
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		// "/default.api.oneops.netdev.v1.OneopsNetdev/DisplaySwitchPortVlans"
		grpcService, grpcMethod, err := opt.parseGRPCMethod(info.FullMethod)
		if err != nil {
			opt.logger.Warn(err.Error())
			return handler(ctx, req)
		}

		if !opt.auditRequired(grpcService, grpcMethod) {
			return handler(ctx, req)
		}

		ed := newEventDataFromContext(ctx, opt, grpcService, grpcMethod)

		// 记录请求体
		if opt.level == LevelRequest || opt.level == LevelRequestResponse {
			ed.setRequestObject(req)
		}

		if err := ed.sendEvent(ctx); err != nil {
			return nil, errs.Unavailable(ctx).WithMessage(err.Error())
		}

		resp, err := handler(ctx, req)

		// 记录响应体审计阶段
		if opt.level == LevelRequestResponse {
			ed.setResponseObject(err, resp)

			if sendErr := ed.sendEvent(ctx); sendErr != nil {
				return nil, errs.Unavailable(ctx).WithMessage(sendErr.Error())
			}
		}

		return resp, err
	}
}

// StreamServerInterceptor 审计事件 grpc stream 拦截器
func StreamServerInterceptor(opts ...Option) grpc.StreamServerInterceptor {
	opt := defaultOption

	for _, o := range opts {
		o(opt)
	}

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		// "/default.api.oneops.netdev.v1.OneopsNetdev/DisplaySwitchPortVlans"
		grpcService, grpcMethod, err := opt.parseGRPCMethod(info.FullMethod)
		if err != nil {
			opt.logger.Warn(err.Error())
			return handler(srv, ss)
		}

		if !opt.auditRequired(grpcService, grpcMethod) {
			return handler(srv, ss)
		}

		x := &serverStream{ServerStream: ss, opt: opt, grpcService: grpcService, grpcMethod: grpcMethod}
		return handler(srv, x)
	}
}
