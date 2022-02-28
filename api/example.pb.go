// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: proto/v1/example.proto

// TODO; 根据具体的微服务名称做更改

package api

import (
	encoding_binary "encoding/binary"
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/gogo/protobuf/proto"
	_ "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger/options"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type ExampleRequest struct {
	// Name 该字段的备注，这里把它设置为必填属性
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Value 该字段的备注，这里设置它默认值为3.14
	Value float32 `protobuf:"fixed32,2,opt,name=value,proto3" json:"value,omitempty"`
}

func (m *ExampleRequest) Reset()         { *m = ExampleRequest{} }
func (m *ExampleRequest) String() string { return proto.CompactTextString(m) }
func (*ExampleRequest) ProtoMessage()    {}
func (*ExampleRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_e9bcb6e413bba4d7, []int{0}
}
func (m *ExampleRequest) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ExampleRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ExampleRequest.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ExampleRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExampleRequest.Merge(m, src)
}
func (m *ExampleRequest) XXX_Size() int {
	return m.Size()
}
func (m *ExampleRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ExampleRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ExampleRequest proto.InternalMessageInfo

func (m *ExampleRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *ExampleRequest) GetValue() float32 {
	if m != nil {
		return m.Value
	}
	return 0
}

type ExampleResponse struct {
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (m *ExampleResponse) Reset()         { *m = ExampleResponse{} }
func (m *ExampleResponse) String() string { return proto.CompactTextString(m) }
func (*ExampleResponse) ProtoMessage()    {}
func (*ExampleResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_e9bcb6e413bba4d7, []int{1}
}
func (m *ExampleResponse) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ExampleResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ExampleResponse.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ExampleResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExampleResponse.Merge(m, src)
}
func (m *ExampleResponse) XXX_Size() int {
	return m.Size()
}
func (m *ExampleResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ExampleResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ExampleResponse proto.InternalMessageInfo

func (m *ExampleResponse) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func init() {
	proto.RegisterType((*ExampleRequest)(nil), "grpc.kit.api.proto.v1.ExampleRequest")
	proto.RegisterType((*ExampleResponse)(nil), "grpc.kit.api.proto.v1.ExampleResponse")
}

func init() { proto.RegisterFile("proto/v1/example.proto", fileDescriptor_e9bcb6e413bba4d7) }

var fileDescriptor_e9bcb6e413bba4d7 = []byte{
	// 465 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x5c, 0x91, 0xb1, 0x6b, 0x1b, 0x3f,
	0x14, 0xc7, 0xf5, 0x42, 0x7e, 0x81, 0x1c, 0xfc, 0xda, 0x72, 0x25, 0xc1, 0x84, 0xf2, 0x7c, 0x1c,
	0x1d, 0xb2, 0xf8, 0x0e, 0x3b, 0x99, 0xdc, 0xe9, 0x4c, 0xfb, 0x0f, 0xb8, 0x5b, 0x3b, 0xc9, 0x87,
	0xaa, 0x1c, 0xb6, 0x4f, 0xaa, 0x4f, 0x76, 0x12, 0x42, 0x20, 0x94, 0x0c, 0x5d, 0x0a, 0xc5, 0x69,
	0x97, 0x42, 0x4b, 0xc7, 0x6c, 0x4d, 0xa7, 0x86, 0x76, 0xc9, 0xe8, 0xd1, 0x74, 0xf2, 0x98, 0x93,
	0x48, 0xe2, 0x31, 0x63, 0xc7, 0xe2, 0x93, 0x09, 0xa6, 0x8b, 0x78, 0xef, 0xab, 0xa7, 0xcf, 0xf7,
	0x2b, 0x9e, 0xb3, 0x2e, 0x7b, 0x42, 0x89, 0x70, 0x50, 0x0d, 0xd9, 0x1e, 0xed, 0xca, 0x0e, 0x0b,
	0x0a, 0xc1, 0x5d, 0xe3, 0x3d, 0x19, 0x07, 0xed, 0x44, 0x05, 0x54, 0x26, 0x56, 0x0b, 0x06, 0xd5,
	0x8d, 0x0a, 0x4f, 0xd4, 0x4e, 0xbf, 0x15, 0xc4, 0xa2, 0x1b, 0x72, 0xc1, 0x45, 0x58, 0xdc, 0xb4,
	0xfa, 0xaf, 0x8a, 0xce, 0xb2, 0x66, 0x95, 0x7d, 0xb1, 0xf1, 0x7c, 0x71, 0xbc, 0x27, 0xe3, 0x0a,
	0x8b, 0x45, 0xb6, 0x9f, 0x29, 0x36, 0x6f, 0x39, 0x55, 0x6c, 0x97, 0xee, 0x5b, 0x4a, 0x5c, 0xe1,
	0x2c, 0xad, 0x64, 0xbb, 0x94, 0x73, 0xd6, 0x0b, 0x85, 0x54, 0x89, 0x48, 0xb3, 0x90, 0xa6, 0xa9,
	0x50, 0xb4, 0xa8, 0x2d, 0xd4, 0xff, 0x0c, 0xce, 0xbd, 0x67, 0x36, 0x6c, 0x93, 0xbd, 0xee, 0xb3,
	0x4c, 0xb9, 0x8f, 0x9d, 0xe5, 0x94, 0x76, 0x59, 0x09, 0x3c, 0xd8, 0x5c, 0x6d, 0x3c, 0x18, 0x46,
	0xff, 0xef, 0x8d, 0xe0, 0x08, 0xe0, 0x37, 0x14, 0x7a, 0xb3, 0x38, 0xdd, 0xb2, 0xf3, 0xdf, 0x80,
	0x76, 0xfa, 0xac, 0xb4, 0xe4, 0xc1, 0xe6, 0x52, 0x63, 0x75, 0x18, 0xad, 0xd4, 0x97, 0xb7, 0x82,
	0xea, 0x76, 0xd3, 0xea, 0xf5, 0xa7, 0xc3, 0x28, 0x72, 0xca, 0xb5, 0xf5, 0x39, 0xfd, 0xe6, 0xd3,
	0xf1, 0xf4, 0xdb, 0x8f, 0xeb, 0xef, 0x6f, 0x6e, 0x7e, 0x9d, 0x5c, 0x7f, 0x39, 0x9e, 0xc3, 0x6a,
	0xe8, 0x3e, 0x3a, 0xf0, 0xfc, 0x59, 0xe9, 0xd7, 0x3d, 0x7f, 0x87, 0x75, 0x3a, 0xc2, 0x2b, 0x7e,
	0xd3, 0x4e, 0x94, 0xef, 0x1d, 0xfa, 0x2f, 0x9d, 0xfb, 0x77, 0xf1, 0x32, 0x29, 0xd2, 0x8c, 0xb9,
	0xee, 0x62, 0x3e, 0x9b, 0xa6, 0xbe, 0x3d, 0x8c, 0xaa, 0x4e, 0x69, 0xd1, 0xec, 0xea, 0xe4, 0xdd,
	0xd5, 0xcf, 0x0f, 0xd6, 0xac, 0xb6, 0xe6, 0x3e, 0x3c, 0x98, 0x9b, 0xf8, 0x77, 0xf4, 0xc3, 0xc6,
	0x47, 0x18, 0xe5, 0x08, 0xe3, 0x1c, 0x61, 0x92, 0x23, 0x5c, 0xe6, 0x48, 0xa6, 0x39, 0x92, 0xdb,
	0x1c, 0xc9, 0x9f, 0x1c, 0xc9, 0x91, 0x46, 0xf2, 0x56, 0x23, 0x39, 0xd5, 0x08, 0x67, 0x1a, 0xc9,
	0xb9, 0x46, 0x72, 0xa1, 0x91, 0x8c, 0x34, 0xc2, 0x58, 0x23, 0x4c, 0x34, 0x92, 0x4b, 0x8d, 0x30,
	0xd5, 0x08, 0xb7, 0xb3, 0x59, 0x83, 0xe4, 0xbd, 0x41, 0xf2, 0xd5, 0x20, 0x39, 0x35, 0x08, 0x67,
	0x06, 0xe1, 0xdc, 0x20, 0x5c, 0x18, 0x24, 0x23, 0x83, 0x64, 0x6c, 0x90, 0x4c, 0x0c, 0x92, 0x17,
	0xe5, 0x7f, 0x17, 0xd9, 0x4e, 0x54, 0x28, 0xdb, 0x3c, 0xa4, 0x32, 0x79, 0x42, 0x65, 0xd2, 0x5a,
	0x29, 0x76, 0xb3, 0xf5, 0x37, 0x00, 0x00, 0xff, 0xff, 0x19, 0xba, 0x72, 0x4e, 0x50, 0x02, 0x00,
	0x00,
}

func (this *ExampleRequest) Compare(that interface{}) int {
	if that == nil {
		if this == nil {
			return 0
		}
		return 1
	}

	that1, ok := that.(*ExampleRequest)
	if !ok {
		that2, ok := that.(ExampleRequest)
		if ok {
			that1 = &that2
		} else {
			return 1
		}
	}
	if that1 == nil {
		if this == nil {
			return 0
		}
		return 1
	} else if this == nil {
		return -1
	}
	if this.Name != that1.Name {
		if this.Name < that1.Name {
			return -1
		}
		return 1
	}
	if this.Value != that1.Value {
		if this.Value < that1.Value {
			return -1
		}
		return 1
	}
	return 0
}
func (this *ExampleResponse) Compare(that interface{}) int {
	if that == nil {
		if this == nil {
			return 0
		}
		return 1
	}

	that1, ok := that.(*ExampleResponse)
	if !ok {
		that2, ok := that.(ExampleResponse)
		if ok {
			that1 = &that2
		} else {
			return 1
		}
	}
	if that1 == nil {
		if this == nil {
			return 0
		}
		return 1
	} else if this == nil {
		return -1
	}
	if this.Name != that1.Name {
		if this.Name < that1.Name {
			return -1
		}
		return 1
	}
	return 0
}
func (this *ExampleRequest) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*ExampleRequest)
	if !ok {
		that2, ok := that.(ExampleRequest)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.Name != that1.Name {
		return false
	}
	if this.Value != that1.Value {
		return false
	}
	return true
}
func (this *ExampleResponse) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*ExampleResponse)
	if !ok {
		that2, ok := that.(ExampleResponse)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if this.Name != that1.Name {
		return false
	}
	return true
}
func (m *ExampleRequest) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ExampleRequest) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ExampleRequest) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.Value != 0 {
		i -= 4
		encoding_binary.LittleEndian.PutUint32(dAtA[i:], uint32(math.Float32bits(float32(m.Value))))
		i--
		dAtA[i] = 0x15
	}
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintExample(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *ExampleResponse) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ExampleResponse) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ExampleResponse) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.Name) > 0 {
		i -= len(m.Name)
		copy(dAtA[i:], m.Name)
		i = encodeVarintExample(dAtA, i, uint64(len(m.Name)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintExample(dAtA []byte, offset int, v uint64) int {
	offset -= sovExample(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *ExampleRequest) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovExample(uint64(l))
	}
	if m.Value != 0 {
		n += 5
	}
	return n
}

func (m *ExampleResponse) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.Name)
	if l > 0 {
		n += 1 + l + sovExample(uint64(l))
	}
	return n
}

func sovExample(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozExample(x uint64) (n int) {
	return sovExample(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *ExampleRequest) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowExample
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ExampleRequest: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ExampleRequest: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExample
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthExample
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthExample
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 5 {
				return fmt.Errorf("proto: wrong wireType = %d for field Value", wireType)
			}
			var v uint32
			if (iNdEx + 4) > l {
				return io.ErrUnexpectedEOF
			}
			v = uint32(encoding_binary.LittleEndian.Uint32(dAtA[iNdEx:]))
			iNdEx += 4
			m.Value = float32(math.Float32frombits(v))
		default:
			iNdEx = preIndex
			skippy, err := skipExample(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthExample
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ExampleResponse) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowExample
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ExampleResponse: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ExampleResponse: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Name", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowExample
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthExample
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthExample
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Name = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipExample(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthExample
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipExample(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowExample
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowExample
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowExample
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthExample
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupExample
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthExample
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthExample        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowExample          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupExample = fmt.Errorf("proto: unexpected end of group")
)
