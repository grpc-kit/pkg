package audit

import (
	"errors"
	"io"

	"google.golang.org/grpc"

	"github.com/grpc-kit/pkg/errs"
)

type serverStream struct {
	grpc.ServerStream

	grpcService string
	grpcMethod  string

	opt *interceptorOption
}

// RecvMsg xx
func (s *serverStream) RecvMsg(m interface{}) error {
	err := s.ServerStream.RecvMsg(m)

	// 客户端关闭连接时，服务端会收到 io.EOF 错误
	if errors.Is(err, io.EOF) {
		return err
	}

	// 记录请求体
	if s.opt.level == LevelRequest || s.opt.level == LevelRequestResponse {
		ctx := s.ServerStream.Context()

		ed := newEventDataFromContext(ctx, s.opt, s.grpcService, s.grpcMethod)
		ed.setRequestObject(m)

		if sendErr := ed.sendEvent(ctx); sendErr != nil {
			return errs.Unavailable(ctx).WithMessage(sendErr.Error())
		}
	}

	return err
}

// SendMsg xx
func (s *serverStream) SendMsg(m interface{}) error {
	err := s.ServerStream.SendMsg(m)

	// 记录响应体
	if s.opt.level == LevelRequestResponse {
		ctx := s.ServerStream.Context()

		ed := newEventDataFromContext(ctx, s.opt, s.grpcService, s.grpcMethod)
		ed.setResponseObject(err, m)

		if sendErr := ed.sendEvent(ctx); sendErr != nil {
			return errs.Unavailable(ctx).WithMessage(sendErr.Error())
		}
	}

	return err
}
