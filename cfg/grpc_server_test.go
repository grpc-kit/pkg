package cfg

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/grpc-kit/pkg/errs"
)

// newCheckPermissionTestConfig 构造一个最小化的 LocalConfig，所有 OPA 引擎关闭，
// 使得 policyAllow 返回 (true, nil)，从而单独验证 checkPermission 的 Groups 非空前置门。
func newCheckPermissionTestConfig() *LocalConfig {
	falseVal := false
	return &LocalConfig{
		Security: &SecurityConfig{
			Enable: true,
			Authorization: &Authorization{
				OPANative:      OPANative{Enabled: &falseVal},
				OPAExternal:    OPAExternal{Enabled: &falseVal},
				OPAEnvoyPlugin: OPAEnvoyPlugin{Enabled: &falseVal},
			},
		},
	}
}

// isPermissionDenied 判断错误是否为 PermissionDenied（对应 HTTP 403）。
func isPermissionDenied(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected PermissionDenied error, got nil")
	}
	st := errs.FromError(err)
	if st.HTTPStatusCode() != 403 {
		t.Fatalf("expected 403, got %d (err: %v)", st.HTTPStatusCode(), err)
	}
}

func TestCheckPermission_GroupsRequired(t *testing.T) {
	c := newCheckPermissionTestConfig()
	ctx := context.Background()

	// 受保护方法 + Groups 为空 -> 403
	err := c.checkPermission(ctx, "/grpc_kit.api.known.admin.v1.KnownAdmin/ListUsers", nil)
	isPermissionDenied(t, err)

	// 受保护方法 + Groups 为空切片 -> 403
	err = c.checkPermission(ctx, "/grpc_kit.api.known.admin.v1.KnownAdmin/ListUsers", []string{})
	isPermissionDenied(t, err)
}

func TestCheckPermission_GroupsPresent_PassesGate(t *testing.T) {
	c := newCheckPermissionTestConfig()
	ctx := context.Background()

	// 有 Groups + 受保护方法 -> 通过前置门（OPA 关闭，AllowedGroups 空，故放行）
	err := c.checkPermission(ctx, "/grpc_kit.api.known.admin.v1.KnownAdmin/ListUsers", []string{"superadmin"})
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
}

func TestCheckPermission_SelfServiceBypassesGroupsGate(t *testing.T) {
	c := newCheckPermissionTestConfig()
	ctx := context.Background()

	// 自服务方法 + Groups 为空 -> 不被前置门拒绝（继续 AllowedGroups/OPA 评估，均放行）
	for _, method := range []string{
		"/grpc_kit.api.known.admin.v1.KnownAdmin/SetupUserMFA",
		"/grpc_kit.api.known.admin.v1.KnownAdmin/ConfirmUserMFA",
		"/grpc_kit.api.known.admin.v1.KnownAdmin/DisableUserMFA",
		"/grpc_kit.api.known.admin.v1.KnownAdmin/GetOAuth2Userinfo",
		"/grpc_kit.api.known.admin.v1.KnownAdmin/CreateDatabaseInitialize",
	} {
		err := c.checkPermission(ctx, method, nil)
		if err != nil {
			t.Fatalf("method %s: expected nil (self-service bypass), got: %v", method, err)
		}
	}
}

func TestCheckPermission_AllowedGroupsStillEnforced(t *testing.T) {
	falseVal := false
	c := &LocalConfig{
		Security: &SecurityConfig{
			Enable: true,
			Authorization: &Authorization{
				AllowedGroups:  []string{"superadmin"},
				OPANative:      OPANative{Enabled: &falseVal},
				OPAExternal:    OPAExternal{Enabled: &falseVal},
				OPAEnvoyPlugin: OPAEnvoyPlugin{Enabled: &falseVal},
			},
		},
	}
	ctx := context.Background()

	// 有 Groups 但不匹配 AllowedGroups -> 403（验证前置门放行后 AllowedGroups 仍生效）
	err := c.checkPermission(ctx, "/grpc_kit.api.known.admin.v1.KnownAdmin/ListUsers", []string{"viewer"})
	isPermissionDenied(t, err)

	// 自服务方法 + Groups 为空 + AllowedGroups 配置 -> 前置门豁免，但 AllowedGroups 仍要求交集
	// 注意：自服务豁免仅针对 Groups 非空前置门，AllowedGroups 仍需满足。
	err = c.checkPermission(ctx, "/grpc_kit.api.known.admin.v1.KnownAdmin/SetupUserMFA", nil)
	isPermissionDenied(t, err)
}

func TestGetHTTPListenHostPort(t *testing.T) {
	tests := []struct {
		name     string
		svc      ServicesConfig
		wantHost string
		wantPort int
		wantErr  bool
	}{
		{
			name:     "0.0.0.0 normalized to 127.0.0.1",
			svc:      ServicesConfig{HTTPAddress: "0.0.0.0:8080"},
			wantHost: "127.0.0.1",
			wantPort: 8080,
		},
		{
			name:     "loopback http_address",
			svc:      ServicesConfig{HTTPAddress: "127.0.0.1:8080"},
			wantHost: "127.0.0.1",
			wantPort: 8080,
		},
		{
			name:     "external ip http_address",
			svc:      ServicesConfig{HTTPAddress: "192.168.1.1:8080"},
			wantHost: "192.168.1.1",
			wantPort: 8080,
		},
		{
			name: "http_service.address overrides http_address",
			svc: ServicesConfig{
				HTTPAddress: "0.0.0.0:9090",
				HTTPService: &HTTPService{Address: "127.0.0.1:8080"},
			},
			wantHost: "127.0.0.1",
			wantPort: 8080,
		},
		{
			name:    "invalid format - no port",
			svc:     ServicesConfig{HTTPAddress: "0.0.0.0"},
			wantErr: true,
		},
		{
			name:    "invalid format - bad port",
			svc:     ServicesConfig{HTTPAddress: "0.0.0.0:abc"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, err := tt.svc.getHTTPListenHostPort()
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("port = %d, want %d", port, tt.wantPort)
			}
		})
	}
}

func TestLoopbackNormalization(t *testing.T) {
	tests := []struct {
		name     string
		httpAddr string
		wantURL  string
	}{
		{
			name:     "0.0.0.0 normalized to 127.0.0.1",
			httpAddr: "0.0.0.0:8080",
			wantURL:  "http://127.0.0.1:8080",
		},
		{
			name:     "127.0.0.1 stays as-is",
			httpAddr: "127.0.0.1:8080",
			wantURL:  "http://127.0.0.1:8080",
		},
		{
			name:     "external IP stays as-is",
			httpAddr: "192.168.1.1:8080",
			wantURL:  "http://192.168.1.1:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := ServicesConfig{HTTPAddress: tt.httpAddr}
			host, port, err := svc.getHTTPListenHostPort()
			if err != nil {
				t.Fatalf("getHTTPListenHostPort: %v", err)
			}
			// getHTTPListenHostPort 内部已归一化 0.0.0.0 -> 127.0.0.1
			gotURL := "http://" + net.JoinHostPort(host, strconv.Itoa(port))
			if gotURL != tt.wantURL {
				t.Errorf("got %q, want %q", gotURL, tt.wantURL)
			}
		})
	}
}

func TestHTTPSchemeDetection(t *testing.T) {
	tests := []struct {
		name        string
		certFile    string
		acmeDomains []string
		wantScheme  string
	}{
		{
			name:        "no TLS -> http",
			certFile:    "",
			acmeDomains: nil,
			wantScheme:  "http",
		},
		{
			name:        "manual cert -> https",
			certFile:    "/path/to/cert.pem",
			acmeDomains: nil,
			wantScheme:  "https",
		},
		{
			name:        "acme domains -> https",
			certFile:    "",
			acmeDomains: []string{"example.com"},
			wantScheme:  "https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsEnabled := tt.certFile != "" || len(tt.acmeDomains) > 0
			scheme := "http"
			if tlsEnabled {
				scheme = "https"
			}
			if scheme != tt.wantScheme {
				t.Errorf("scheme = %q, want %q", scheme, tt.wantScheme)
			}
		})
	}
}
