package errors

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
)

// Response 统一错误响应格式
// 实现 github.com/golang/protobuf/proto.Message 接口
type Response struct {
	Error Status `protobuf:"bytes,1,name=error" json:"error"`
}

// Reset 为实现 proto.Message 接口定义
func (r *Response) Reset() { *r = Response{} }

// String 为实现 proto.Message 接口定义
func (r *Response) String() string { return proto.CompactTextString(r) }

// ProtoMessage 为实现 proto.Message 接口定义
func (e *Response) ProtoMessage() {}

// Status 统一错误响应内容
type Status struct {
	Code    int32      `protobuf:"varint,1,name=code" json:"code"`
	Status  string     `protobuf:"bytes,2,name=status" json:"status"`
	Message string     `protobuf:"bytes,3,name=message" json:"message"`
	Details []*any.Any `protobuf:"bytes,4,rep,name=details" json:"details"`
}

// Reset 为实现 proto.Message 接口定义
func (s *Status) Reset() { *s = Status{} }

// String 为实现 proto.Message 接口定义
func (s *Status) String() string { return proto.CompactTextString(s) }

// ProtoMessage 为实现 proto.Message 接口定义
func (s *Status) ProtoMessage() {}
