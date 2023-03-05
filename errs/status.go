package errs

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	statusv1 "github.com/grpc-kit/pkg/api/known/status/v1"
)

// Status 统一错误响应内容
type Status struct {
	*statusv1.Status
}

// New 创建一个基础错误类型
func New(code int32, message string) *Status {
	s := &Status{
		&statusv1.Status{
			Code:    code,
			Status:  codes.Code(code).String(),
			Message: message,
		},
	}
	return s
}

// FromStatus 用于转换 google.rpc.Status 类型为统一错误响应结构
func FromStatus(s *status.Status) *Status {
	if s == nil {
		return Unknown(context.Background())
	}

	t := &Status{
		&statusv1.Status{
			Code:    s.Proto().Code,
			Status:  s.Code().String(),
			Message: s.Proto().Message,
			Details: s.Proto().Details,
		},
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
	return status.New(codes.Code(s.Code), s.Message).Err()
}

// Error 为实现 error 接口定义
func (s *Status) Error() string {
	return fmt.Sprintf("rpc error: code = %v desc = %s", s.Status, s.Message)
}

// WithMessage 覆盖默认的错误说明
func (s *Status) WithMessage(msg string) *Status {
	s.Message = msg
	return s
}

// WithDetails returns a new status with the provided details messages appended to the status.
func (s *Status) WithDetails(details ...proto.Message) *Status {
	for _, detail := range details {
		s = s.AppendDetail(detail)
	}
	return s
}

// AppendDetail 添加错误详情内容
func (s *Status) AppendDetail(detail proto.Message) *Status {
	a, err := anypb.New(detail)
	if err == nil {
		s.Details = append(s.Details, a)
	}
	return s
}

// HTTPStatusCode 用于转换错误代码为标准HTTP状态码
func (s *Status) HTTPStatusCode() int {
	return mapping(codes.Code(s.Code))
}

// GRPCStatus 用于返回google grpc status.Status结构
func (s *Status) GRPCStatus() *status.Status {
	if s == nil {
		return nil
	}
	return status.New(codes.Code(s.Code), s.Message)
}
