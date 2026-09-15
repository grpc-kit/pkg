package tools

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/grpc-kit/pkg/admin/openapiconfig"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/genproto/googleapis/api/serviceconfig"
)

type bridgeRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f bridgeRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

var _ func(
	*mcp.Server,
	GRPCConnFunc,
	*http.Client,
	string,
	*serviceconfig.Service,
	*openapiconfig.OpenAPIConfig,
	fs.FS,
	string,
	[]string,
	*slog.Logger,
) error = AutoBridge

func TestBridgeHandlerWithLogger(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
	req := &mcp.CallToolRequest{
		Params: &mcp.CallToolParamsRaw{Arguments: []byte(`{}`)},
	}

	result, err := bridgeHandler(
		t.Context(),
		req,
		&http.Client{},
		"http://gateway.test",
		"GET",
		"/v1/items/{id}",
		"",
		nil,
		logger,
	)
	if err != nil {
		t.Fatalf("bridgeHandler() error = %v", err)
	}
	if !result.IsError {
		t.Fatal("bridgeHandler() result is not an error")
	}
	if count := strings.Count(output.String(), "\n"); count != 2 {
		t.Fatalf("log line count = %d, want 2; output = %q", count, output.String())
	}
	if !strings.Contains(output.String(), `"msg":"MCP tool invocation received"`) {
		t.Fatalf("invoked message was not preserved: %q", output.String())
	}
	if !strings.Contains(output.String(), `"msg":"MCP tool invocation rejected: missing path parameter"`) {
		t.Fatalf("abort message was not preserved: %q", output.String())
	}
	for _, forbidden := range []string{"get_item", "GET", `"id"`, `"args"`, `"error":`, `"event":`} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("dynamic value %q leaked into bridge log: %q", forbidden, output.String())
		}
	}
}

func TestBridgeHandlerLogsDoNotExposeRequestResponseOrError(t *testing.T) {
	const (
		requestValue  = "request-sensitive"
		responseValue = "response-sensitive"
		transportErr  = "transport-sensitive"
		gatewayHost   = "gateway-sensitive.test"
	)

	tests := []struct {
		name      string
		transport bridgeRoundTripperFunc
		wantLines int
	}{
		{
			name: "response",
			transport: func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(`{"token":"` + responseValue + `"}`)),
				}, nil
			},
			wantLines: 4,
		},
		{
			name: "transport error",
			transport: func(*http.Request) (*http.Response, error) {
				return nil, errors.New(transportErr)
			},
			wantLines: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug}))
			req := &mcp.CallToolRequest{
				Params: &mcp.CallToolParamsRaw{Arguments: []byte(`{"payload":"` + requestValue + `"}`)},
			}

			result, err := bridgeHandler(
				t.Context(),
				req,
				&http.Client{Transport: tt.transport},
				"http://"+gatewayHost,
				"POST",
				"/v1/items",
				"*",
				nil,
				logger,
			)
			if err != nil {
				t.Fatalf("bridgeHandler() error = %v", err)
			}
			if result == nil {
				t.Fatal("bridgeHandler() result = nil")
			}
			if got := strings.Count(output.String(), "\n"); got != tt.wantLines {
				t.Fatalf("log line count = %d, want %d; output=%q", got, tt.wantLines, output.String())
			}
			for _, forbidden := range []string{
				requestValue,
				responseValue,
				transportErr,
				gatewayHost,
				`"args"`,
				`"body"`,
				`"error":`,
				`"event":`,
			} {
				if strings.Contains(output.String(), forbidden) {
					t.Fatalf("sensitive value %q leaked into bridge log: %q", forbidden, output.String())
				}
			}
		})
	}
}
