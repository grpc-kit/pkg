package audit

import (
	"context"
	"fmt"
	"strings"
	"time"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/event"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

// UnaryServerInterceptor xx
func UnaryServerInterceptor(opts ...Option) grpc.UnaryServerInterceptor {
	opt := &interceptorOption{}

	for _, o := range opts {
		o(opt)
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		auditEvent := event.New()

		auditEvent.SetSpecVersion(event.CloudEventsVersionV1)
		auditEvent.SetSource(opt.serviceName)
		auditEvent.SetType(fmt.Sprintf("%v.internal.audit", opt.serviceCode))

		parts := strings.Split(info.FullMethod, "/")
		auditEvent.SetSubject(parts[len(parts)-1])

		// content := make(map[string]interface{}, 0)
		// username, _ := c.UsernameFrom(ctx)
		// groups, _ := c.GroupsFrom(ctx)

		content := EventData{
			Level:                    opt.level,
			ServiceName:              opt.serviceName,
			ServiceCode:              opt.serviceCode,
			RequestReceivedTimestamp: time.Now(),
			GRPCService:              parts[1],
			GRPCMethod:               parts[len(parts)-1],
			SourceIPs:                rpc.ClientSourceIPs(ctx),

			/*
				User: struct {
					UID      string              `json:"uid"`
					Username string              `json:"username"`
					Groups   []string            `json:"groups"`
					Extra    map[string][]string `json:"extra"`
				}{UID: username, Username: username, Groups: groups, Extra: make(map[string][]string, 0)},
			*/

			UserAgent: rpc.ClientUserAgent(ctx),
			RequestID: opt.getTraceID(ctx),
		}

		// 记录请求体
		if opt.level == LevelRequest || opt.level == LevelRequestResponse {
			if protoReq, ok := req.(proto.Message); ok {
				xxx, err := opt.marshal.Marshal(protoReq)
				if err == nil {
					content.RequestObject = string(xxx)
				}
			} else {
				fmt.Printf("Request: %+v", req)
			}
		}

		resp, err := handler(ctx, req)

		// 记录响应体
		if opt.level == LevelRequestResponse {
			if protoResp, ok := resp.(proto.Message); ok {
				xxx, err := opt.marshal.Marshal(protoResp)
				if err == nil {
					content.ResponseObject = string(xxx)
				}
			}
		}

		// 只有在成功执行后才发送审计事件
		content.StageTimestamp = time.Now()
		if err = auditEvent.SetData(event.ApplicationJSON, content); err == nil {
			// DEBUG
			/*
				rawBody, err := auditEvent.MarshalJSON()
				if err == nil {
					fmt.Println(string(rawBody))
				}
			*/

			res := opt.client.Send(ctx, auditEvent)
			if cloudevents.IsUndelivered(res) {
				fmt.Println("send audit event ok")
			}
		} else {
			fmt.Println("send audit event fail")
		}

		return resp, err
	}
}
