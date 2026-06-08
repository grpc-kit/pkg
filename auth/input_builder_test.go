package auth

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// fakeServerTransportStream 是 grpc.ServerTransportStream 的最小实现，
// 仅用于在 input_builder 单测中让 `grpc.Method(ctx)` 能取到我们设定的 full method。
type fakeServerTransportStream struct {
	method string
}

func (f *fakeServerTransportStream) Method() string                  { return f.method }
func (f *fakeServerTransportStream) SetHeader(metadata.MD) error     { return nil }
func (f *fakeServerTransportStream) SendHeader(metadata.MD) error    { return nil }
func (f *fakeServerTransportStream) SetTrailer(metadata.MD) error    { return nil }

// newGRPCCtx 构造一个带 full method 的 gRPC server ctx，模拟拦截器栈调用。
func newGRPCCtx(method string) context.Context {
	return grpc.NewContextWithServerTransportStream(
		context.Background(),
		&fakeServerTransportStream{method: method},
	)
}

// newDictForBuilder 构造一份覆盖 input_builder 反查路径的最小静态字典。
// 不走 FS / OpenAPI 解析，直接手填，保证测试聚焦于反查行为。
func newDictForBuilder() *StaticDict {
	return &StaticDict{
		Services: map[string]*Service{},
		RPCRoutes: map[string]string{
			"/grpc_kit.api.known.admin.v1.KnownAdmin/CreateAuthLogin": "known.admin.api:CreateAuthLogin",
			"/netdev.v1.oneops.NetdevService/DisplaySwitchBGPAllSummary": "netdev.v1.oneops:DisplaySwitchBGPAllSummary",
		},
		GatewayRoutes: []GatewayRoute{
			{Method: "GET", PathTemplate: "/ping", ActionID: "known.admin.api:Ping"},
			{Method: "POST", PathTemplate: "/builtin/admin/api/v1/auth/login", ActionID: "known.admin.api:CreateAuthLogin"},
			// 带 `{}` 占位符的 gateway 路由 —— P5 不支持模板解析，应被静默跳过。
			{Method: "GET", PathTemplate: "/v1/users/{user_id}", ActionID: "known.admin.api:GetUser"},
		},
	}
}

func TestFromGRPCContext(t *testing.T) {
	dict := newDictForBuilder()

	tests := []struct {
		name         string
		ctx          context.Context
		dict         *StaticDict
		wantService  string
		wantAction   string
		wantActionID string
	}{
		{
			name:         "rpc_hit_admin",
			ctx:          newGRPCCtx("/grpc_kit.api.known.admin.v1.KnownAdmin/CreateAuthLogin"),
			dict:         dict,
			wantService:  "known.admin.api",
			wantAction:   "CreateAuthLogin",
			wantActionID: "known.admin.api:CreateAuthLogin",
		},
		{
			name:         "rpc_hit_oneops",
			ctx:          newGRPCCtx("/netdev.v1.oneops.NetdevService/DisplaySwitchBGPAllSummary"),
			dict:         dict,
			wantService:  "netdev.v1.oneops",
			wantAction:   "DisplaySwitchBGPAllSummary",
			wantActionID: "netdev.v1.oneops:DisplaySwitchBGPAllSummary",
		},
		{
			name: "rpc_miss_unknown_method",
			ctx:  newGRPCCtx("/some.unknown.Service/DoStuff"),
			dict: dict,
			// 全空
		},
		{
			name: "no_grpc_method_in_ctx",
			ctx:  context.Background(),
			dict: dict,
		},
		{
			name: "nil_dict_returns_empty",
			ctx:  newGRPCCtx("/grpc_kit.api.known.admin.v1.KnownAdmin/CreateAuthLogin"),
			dict: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := FromGRPCContext(tc.ctx, tc.dict)
			if in == nil {
				t.Fatalf("FromGRPCContext returned nil")
			}
			if got := in.GrpcKit.Service; got != tc.wantService {
				t.Errorf("Service = %q, want %q", got, tc.wantService)
			}
			if got := in.GrpcKit.Action; got != tc.wantAction {
				t.Errorf("Action = %q, want %q", got, tc.wantAction)
			}
			if got := in.GrpcKit.ActionID; got != tc.wantActionID {
				t.Errorf("ActionID = %q, want %q", got, tc.wantActionID)
			}
		})
	}
}

func TestFromHTTPRequest(t *testing.T) {
	dict := newDictForBuilder()

	mustReq := func(method, rawPath string) *http.Request {
		t.Helper()
		u, err := url.Parse(rawPath)
		if err != nil {
			t.Fatalf("url.Parse(%q): %v", rawPath, err)
		}
		return &http.Request{Method: method, URL: u}
	}

	tests := []struct {
		name         string
		req          *http.Request
		dict         *StaticDict
		wantService  string
		wantAction   string
		wantActionID string
	}{
		{
			name:         "literal_ping_hit",
			req:          mustReq("GET", "/ping"),
			dict:         dict,
			wantService:  "known.admin.api",
			wantAction:   "Ping",
			wantActionID: "known.admin.api:Ping",
		},
		{
			name:         "literal_login_hit_case_insensitive_method",
			req:          mustReq("post", "/builtin/admin/api/v1/auth/login"), // 小写方法应被规范化
			dict:         dict,
			wantService:  "known.admin.api",
			wantAction:   "CreateAuthLogin",
			wantActionID: "known.admin.api:CreateAuthLogin",
		},
		{
			name: "method_mismatch",
			req:  mustReq("POST", "/ping"), // /ping 注册的是 GET
			dict: dict,
		},
		{
			name: "template_with_placeholders_not_matched_p5",
			req:  mustReq("GET", "/v1/users/u-001"), // PathTemplate 是 /v1/users/{user_id}
			dict: dict,
		},
		{
			name: "unknown_path",
			req:  mustReq("GET", "/no/such/endpoint"),
			dict: dict,
		},
		{
			name: "nil_request",
			req:  nil,
			dict: dict,
		},
		{
			name: "nil_dict",
			req:  mustReq("GET", "/ping"),
			dict: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := FromHTTPRequest(context.Background(), tc.req, tc.dict)
			if in == nil {
				t.Fatalf("FromHTTPRequest returned nil")
			}
			if got := in.GrpcKit.Service; got != tc.wantService {
				t.Errorf("Service = %q, want %q", got, tc.wantService)
			}
			if got := in.GrpcKit.Action; got != tc.wantAction {
				t.Errorf("Action = %q, want %q", got, tc.wantAction)
			}
			if got := in.GrpcKit.ActionID; got != tc.wantActionID {
				t.Errorf("ActionID = %q, want %q", got, tc.wantActionID)
			}
		})
	}
}

func TestInputToMap(t *testing.T) {
	in := &Input{
		GrpcKit: GrpcKit{
			Service:  "known.admin.api",
			Action:   "CreateAuthLogin",
			ActionID: "known.admin.api:CreateAuthLogin",
		},
	}
	m := in.ToMap()

	// subject 始终存在（即使为空 map），便于 Rego 引用 input.subject.* 不会 undefined。
	if _, ok := m["subject"]; !ok {
		t.Errorf("ToMap missing subject key")
	}

	gk, ok := m["grpc_kit"].(map[string]any)
	if !ok {
		t.Fatalf("grpc_kit not a map[string]any, got %T", m["grpc_kit"])
	}
	if got := gk["service"]; got != "known.admin.api" {
		t.Errorf("grpc_kit.service = %v, want known.admin.api", got)
	}
	if got := gk["action"]; got != "CreateAuthLogin" {
		t.Errorf("grpc_kit.action = %v, want CreateAuthLogin", got)
	}
	if got := gk["action_id"]; got != "known.admin.api:CreateAuthLogin" {
		t.Errorf("grpc_kit.action_id = %v, want known.admin.api:CreateAuthLogin", got)
	}
}

func TestInputToMap_EmptyKeepsKeys(t *testing.T) {
	// 未命中反查时 ToMap 也应保留键，便于 Rego 用空串区分"未注册动作"。
	in := &Input{}
	m := in.ToMap()
	gk, ok := m["grpc_kit"].(map[string]any)
	if !ok {
		t.Fatalf("grpc_kit not a map[string]any, got %T", m["grpc_kit"])
	}
	for _, key := range []string{"service", "action", "action_id"} {
		v, ok := gk[key]
		if !ok {
			t.Errorf("grpc_kit missing key %q", key)
			continue
		}
		if s, _ := v.(string); s != "" {
			t.Errorf("grpc_kit[%q] = %v, want empty string", key, v)
		}
	}
}

func TestSplitActionID(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantService string
		wantAction  string
		wantID      string
	}{
		{"normal", "known.admin.api:CreateAuthLogin", "known.admin.api", "CreateAuthLogin", "known.admin.api:CreateAuthLogin"},
		{"empty_string", "", "", "", ""},
		{"no_colon", "abc", "", "", "abc"},
		{"colon_at_start", ":CreateAuthLogin", "", "", ":CreateAuthLogin"},
		{"colon_at_end", "known.admin.api:", "", "", "known.admin.api:"},
		{"multiple_colons", "a:b:c", "a", "b:c", "a:b:c"}, // 仅按第一个冒号拆分
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gk := splitActionID(tc.in)
			if gk.Service != tc.wantService {
				t.Errorf("Service = %q, want %q", gk.Service, tc.wantService)
			}
			if gk.Action != tc.wantAction {
				t.Errorf("Action = %q, want %q", gk.Action, tc.wantAction)
			}
			if gk.ActionID != tc.wantID {
				t.Errorf("ActionID = %q, want %q", gk.ActionID, tc.wantID)
			}
		})
	}
}
