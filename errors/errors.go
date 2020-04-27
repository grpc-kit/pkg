package errors

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
)

// Response 实现 github.com/golang/protobuf/proto.Message
type Response struct {
	Error Status `protobuf:"bytes,1,name=error" json:"error"`
}

// Reset xx
func (r *Response) Reset() {
	*r = Response{}
}

// String xx
func (r *Response) String() string {
	return proto.CompactTextString(r)
}

// ProtoMessage xx
func (e *Response) ProtoMessage() {

}

// Status xx
type Status struct {
	Code    int32      `protobuf:"varint,1,name=code" json:"code"`
	Message string     `protobuf:"bytes,2,name=message" json:"message"`
	Details []*any.Any `protobuf:"bytes,3,rep,name=details" json:"details"`
}

// Reset xx
func (s *Status) Reset() {
	*s = Status{}
}

// String xx
func (s *Status) String() string {
	return proto.CompactTextString(s)
}

// ProtoMessage xx
func (s *Status) ProtoMessage() {

}
