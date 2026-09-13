package tools

import (
	"bytes"
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/grpc-kit/pkg/admin/openapiconfig"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/genproto/googleapis/api/serviceconfig"
)

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
		context.Background(),
		req,
		&http.Client{},
		"http://gateway.test",
		"GET",
		"/v1/items/{id}",
		"",
		nil,
		"get_item",
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
	if !strings.Contains(output.String(), `"msg":"tool=get_item invoked method=GET args={}\n"`) {
		t.Fatalf("invoked message was not preserved: %q", output.String())
	}
	if !strings.Contains(output.String(), `"msg":"tool=get_item abort: missing path parameter \"id\""`) {
		t.Fatalf("abort message was not preserved: %q", output.String())
	}
}
