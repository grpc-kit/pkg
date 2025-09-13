package errs

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/protoadapt"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	statusv1 "github.com/grpc-kit/pkg/api/known/status/v1"
)

// Status 统一错误响应内容
type Status struct {
	*statusv1.Status

	anyType []protoadapt.MessageV1
}

// New 创建一个基础错误类型
func New(code codes.Code, message string) *Status {
	s := &Status{
		Status: &statusv1.Status{
			Code:    int32(code),
			Status:  code.String(),
			Message: message,
			Details: make([]*anypb.Any, 0),
		},

		anyType: make([]protoadapt.MessageV1, 0),
	}

	return s
}

// FromStatus 用于转换 google.rpc.Status 类型为统一错误响应结构
func FromStatus(s *status.Status) *Status {
	if s == nil {
		return Unknown(context.Background())
	}

	t := &Status{
		Status: &statusv1.Status{
			Code:    s.Proto().Code,
			Status:  s.Code().String(),
			Message: s.Proto().Message,
			Details: s.Proto().Details,
		},
		anyType: make([]protoadapt.MessageV1, 0),
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

// Err 最后返回 status.statusError 错误类型，只有调用该方法才可以显示 detail 内容
func (s *Status) Err() error {
	statusCode := status.New(codes.Code(s.Code), s.Message)

	if len(s.Details) > 0 {
		for _, detail := range s.Details {
			tmp, err := statusCode.WithDetails(detail)
			if err == nil {
				statusCode = tmp
			}
		}
	}

	if len(s.anyType) > 0 {
		for _, detail := range s.anyType {
			tmp, err := statusCode.WithDetails(detail)
			if err == nil {
				statusCode = tmp
			}
		}
	}

	return statusCode.Err()
}

// Error 为实现 error 接口定义，当直接打印 err 的输出内容
func (s *Status) Error() string {
	return fmt.Sprintf("rpc error: code = %v desc = %s", s.Status, s.Message)
}

// WithLogger 服务端后台输出错误日志，如果开启 debug 模式则带到接口 detail 返回中
func (s *Status) WithLogger(logger *logrus.Entry, format string, err error) *Status {
	if logger == nil {
		return s
	}

	// 仅在后端服务输出错误信息
	logger.Errorf(format, err)

	// 判断是否为开启 debug 模式，如是则填充至 anyType 中
	if logger.Logger != nil && logger.Logger.Level.String() == "debug" {
		l := &errdetails.DebugInfo{
			StackEntries: nil,
			Detail:       fmt.Sprintf(format, err),
		}

		s.anyType = append(s.anyType, l)
	}

	return s
}

// WithErrorInfo 用于输出业务自定义错误状态码等，描述错误的具体原因
/*
  {
    "reason": "API_DISABLED"
    "domain": "googleapis.com"
    "metadata": {
      "resource": "projects/123",
      "service": "pubsub.googleapis.com"
    }
  }

  {
    "reason": "MissingParameter"
    "domain": "grpc-kit.com"
    "metadata": {
      "enUS": "Parameter is missing.",
      "zhCN": "缺少必填参数。"
    }
  }
*/
func (s *Status) WithErrorInfo(reason, domain string, metadata map[string]string) *Status {
	l := &errdetails.ErrorInfo{
		Reason:   reason,
		Domain:   domain,
		Metadata: metadata,
	}
	s.anyType = append(s.anyType, l)
	return s
}

// WithRetryInfo 客户端在收到错误响应后，应等待至少指定的 retry_delay 时间间隔再进行重试
func (s *Status) WithRetryInfo(duration time.Duration) *Status {
	l := &errdetails.RetryInfo{RetryDelay: durationpb.New(duration)}
	s.anyType = append(s.anyType, l)
	return s
}

// WithRequestInfo 添加请求信息，用于服务端记录请求信息，便于客户端追踪问题
func (s *Status) WithRequestInfo(requestID, data string) *Status {
	l := &errdetails.RequestInfo{
		RequestId:   requestID,
		ServingData: data,
	}
	s.anyType = append(s.anyType, l)
	return s
}

// WithResourceInfo 添加资源信息，用于服务端记录资源信息，便于客户端追踪问题
/*
  {
    "resourceType": "type.googleapis.com/google.pubsub.v1.Topic",
    "resourceName": "projects/123/topics/my-topic",
    "owner": "projects/123",
    "description": "The topic already exists."
  }
*/
func (s *Status) WithResourceInfo(resourceType, resourceName, owner, desc string) *Status {
	l := &errdetails.ResourceInfo{
		ResourceType: resourceType,
		ResourceName: resourceName,
		Owner:        owner,
		Description:  desc,
	}
	s.anyType = append(s.anyType, l)
	return s
}

// WithHelp 添加错误帮助信息，用于服务端记录错误信息，便于客户端追踪问题
func (s *Status) WithHelp(helpURL, desc string) *Status {
	l := &errdetails.Help{
		Links: []*errdetails.Help_Link{
			{
				Url:         helpURL,
				Description: desc,
			},
		},
	}
	s.anyType = append(s.anyType, l)
	return s
}

// WithMessage 覆盖默认的错误说明，一般描述为简短的英文内容
func (s *Status) WithMessage(msg string) *Status {
	s.Message = msg
	return s
}

// WithMessageENUS 添加美式英语错误说明
func (s *Status) WithMessageENUS(msg string) *Status {
	l := &errdetails.LocalizedMessage{Locale: "en-US", Message: msg}
	s.anyType = append(s.anyType, l)
	return s
}

// WithMessageZHCN 添加中文简体错误说明
func (s *Status) WithMessageZHCN(msg string) *Status {
	l := &errdetails.LocalizedMessage{Locale: "zh-CN", Message: msg}
	s.anyType = append(s.anyType, l)
	return s
}

// WithMessageZHTW 添加中文繁体错误说明
func (s *Status) WithMessageZHTW(msg string) *Status {
	l := &errdetails.LocalizedMessage{Locale: "zh-TW", Message: msg}
	s.anyType = append(s.anyType, l)
	return s
}

// WithMessageJAJP 添加日本日语错误说明
func (s *Status) WithMessageJAJP(msg string) *Status {
	l := &errdetails.LocalizedMessage{Locale: "ja-JP", Message: msg}
	s.anyType = append(s.anyType, l)
	return s
}

// AppendDetail 添加错误详情内容，仅对接 grpc_kit 公知类型使用，不建议加入外部类型
func (s *Status) AppendDetail(detail protoadapt.MessageV1) *Status {
	a, err := anypb.New(protoadapt.MessageV2Of(detail))
	if err == nil {
		s.Details = append(s.Details, a)
	}
	return s
}

// HTTPStatusCode 用于转换错误代码为标准HTTP状态码
func (s *Status) HTTPStatusCode() int {
	return mapping(codes.Code(s.Code))
}

// ErrorResponseBody 返回客户端 http 错误响应内容
func (s *Status) ErrorResponseBody(ctx context.Context) []byte {
	body := &statusv1.ErrorResponse{
		Error: s.Status,
	}

	// 深拷贝，避免修改原始对象
	t, ok := proto.Clone(s.Status).(*statusv1.Status)
	if ok {
		body.Error = t
		body.Error.Code = int32(s.HTTPStatusCode())
	}

	// 如果类型断言失败，说明 clone 出来类型不对

	rawBody, err := protojson.Marshal(body)
	if err != nil {
		s = Internal(ctx).WithMessage(err.Error())
		body.Error = s.Status
		rawBody, _ = protojson.Marshal(body)
	}

	return rawBody
}

// GRPCStatus 用于返回google grpc status.Status结构
func (s *Status) GRPCStatus() *status.Status {
	if s == nil {
		return nil
	}
	return status.New(codes.Code(s.Code), s.Message)
}

// WithDetails 返回 grpc status 并加入额外自定义的错误详情，建议优先使用以上 WithXXX 方法
func (s *Status) WithDetails(details ...protoadapt.MessageV1) *status.Status {
	// 因通过转换一手 details 会出现在前端错误输出时会多一层 any 嵌套，这里更改为直接返回 grpc Status 结构

	// protojson.Marshal 在处理 google.protobuf.Any 时有两种情况：
	// 1. Any 里包含的是“已注册的类型”（比如 google.rpc.LocalizedMessage、你自定义的 TracingRequest）
	/*
		{
		  "@type": "type.googleapis.com/google.rpc.LocalizedMessage",
		  "locale": "zh-CN",
		  "message": "用户已存在！"
		}
	*/

	// 2. Any 里包含的类型 protojson 不知道怎么解包（没有在全局 proto 注册表里找到）
	/*
		{
			"@type": "type.googleapis.com/google.protobuf.Any",
			"value": {
				"@type": "type.googleapis.com/google.rpc.LocalizedMessage",
				"locale": "zh-CN",
				"message": "用户已存在！"
			}
		}
	*/

	// 原因：
	/*
		google.rpc.LocalizedMessage 是标准类型，Go 的 protobuf runtime 默认是注册过的，所以应该能正常解开。
		之所以出现了 google.protobuf.Any 外套一层，因为在构造 status.WithDetails() 时，传入的不是 *errdetails.LocalizedMessage，而是 *anypb.Any（已经手工封装过一次）。
	*/

	// 示例：
	/*
		st, _ := status.New(codes.AlreadyExists, "xxx").
		    WithDetails(
		        anypb.New(&errdetails.LocalizedMessage{
		            Locale:  "zh-CN",
		            Message: "用户已存在！",
		        }),
		    )
	*/
	/*
		st, _ := status.New(codes.AlreadyExists, "The resource that a client tried to create already exists.").
		    WithDetails(
		        &errdetails.LocalizedMessage{
		            Locale:  "zh-CN",
		            Message: "用户已存在！",
		        },
		        &api.TracingRequest{ // 你自定义的类型
		            Id: "341f7fce42549cdd46d2331c74b837e6",
		        },
		    )
	*/

	t, err := s.GRPCStatus().WithDetails(details...)
	if err != nil {
		return status.Newf(codes.Unknown, "grpc status with detail fail: %v ", err.Error())
	}
	return t
}
