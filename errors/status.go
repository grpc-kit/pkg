package errors

import (
	"context"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FromStatus 用于转换 google.rpc.Status 类型为统一错误响应结构
func FromStatus(s *status.Status) *Status {
	if s == nil {
		return Unknown(context.Background())
	}

	t := &Status{
		Code:    s.Proto().Code,
		Status:  s.Code().String(),
		Message: s.Proto().Message,
		Details: s.Proto().Details,
	}

	return t
}

// FromError 用于转换 status.statusError 类型为统一错误响应结构
func FromError(err error) *Status {
	if err != nil {
		if se, ok := err.(interface {
			GRPCStatus() *status.Status
		}); ok {
			return FromStatus(se.GRPCStatus())
		}
	}

	return Unknown(context.Background())
}

// Err 为返回 status.statusError 错误类型
func (s *Status) Err() error {
	t, _ := status.New(codes.Code(s.Code), s.Message).
		WithDetails(s.details...)

	return t.Err()
}

// Error 为实现 error 接口定义
func (s *Status) Error() string {
	return fmt.Sprintf("rpc error: code = %v desc = %s", s.Code, s.Message)
}

// WithMessage 覆盖默认的错误说明
func (s *Status) WithMessage(msg string) *Status {
	s.Message = msg
	return s
}

// AppendDetail 添加错误详情内容
func (s *Status) AppendDetail(detail proto.Message) *Status {
	s.details = append(s.details, detail)

	any, err := ptypes.MarshalAny(detail)
	if err == nil {
		s.Details = append(s.Details, any)
	}

	return s
}

// HTTPStatusCode 用于转换错误代码为标准HTTP状态码
func (s *Status) HTTPStatusCode() int {
	return mapping(codes.Code(s.Code))
}
