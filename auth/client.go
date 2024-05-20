package auth

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/sdk"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
)

// Client xx
type Client struct {
	config *Config

	envoy   *envoyProxy
	opaSDK  *sdk.OPA
	opaRego rego.PreparedEvalQuery
}

// NewClient xx
func NewClient(config *Config) (*Client, error) {
	c := &Client{
		config: config,
		envoy:  &envoyProxy{},
	}

	return c, nil
}

// InitOPARego xx
func (c *Client) InitOPARego(ctx context.Context, dataRego, dataRBAC []byte) error {
	var jsonData map[string]interface{}
	if err := util.Unmarshal(dataRBAC, &jsonData); err != nil {
		return err
	}

	// 如果客户端提供的 rego 或 rbac 文件为空包含被注释，则使用框架默认规则
	ncl, err := c.nonCommentLineLength(dataRego)
	if err != nil {
		return err
	}
	if ncl == 0 {
		dataRego = c.config.defaultRego()
	}
	ncl, err = c.nonCommentLineLength(dataRBAC)
	if err != nil {
		return err
	}
	if ncl == 0 {
		dataRBAC = c.config.defaultRBAC()
	}

	query, err := rego.New(
		rego.Query(fmt.Sprintf("data.%v.allow", c.config.PackageName)),
		rego.Module("authz.rego", string(dataRego)),
		rego.Store(inmem.NewFromObject(jsonData)),
	).PrepareForEval(ctx)
	if err != nil {
		return err
	}

	c.opaRego = query

	return nil
}

// InitOPASDK xx
func (c *Client) InitOPASDK(ctx context.Context, config []byte) error {
	// opa/sdk
	config = []byte(fmt.Sprintf(`{
		"services": {
			"test": {
				"url": %q
			}
		},
		"bundles": {
			"test": {
				"resource": "/bundle.tar.gz"
			}
		},
		"decision_logs": {
			"console": true
		}
	}`, "http://192.168.0.2:8080"))

	opaSDK, err := sdk.New(ctx, sdk.Options{
		ID:     "opa-test-1",
		Config: bytes.NewReader(config),
	})
	if err != nil {
		return err
	}

	c.opaSDK = opaSDK

	return nil
}

// GRPCAuthnMetadata 把 http 请求信息转换为 grpc 的 metadata 用于鉴权
func (c *Client) GRPCAuthnMetadata(ctx context.Context, req *http.Request) metadata.MD {
	return c.envoy.extractHTTPHeader(ctx, req)
}

func (c *Client) Decision(ctx context.Context) (*sdk.DecisionResult, error) {
	input, err := c.envoy.getCheckRequest(ctx)
	if err != nil {
		return nil, err
	}

	queryAllow := fmt.Sprintf("%v/allow", strings.Replace(c.config.PackageName, ".", "/", -1))
	return c.opaSDK.Decision(ctx, sdk.DecisionOptions{
		Path:  queryAllow,
		Input: input,
	})
}

func (c *Client) Query(ctx context.Context) (rego.ResultSet, error) {
	input, err := c.envoy.getCheckRequest(ctx)
	if err != nil {
		return nil, err
	}

	rawBody, _ := protojson.Marshal(input)
	fmt.Println(string(rawBody))

	return c.opaRego.Eval(ctx, rego.EvalInput(input))
}

// Close xx
func (c *Client) Close(ctx context.Context) {
	if c.opaSDK != nil {
		c.opaSDK.Stop(ctx)
	}
}

// https://pkg.go.dev/github.com/envoyproxy/go-control-plane@v0.12.0/envoy/config/rbac/v3#RBAC
func (c *Client) opaRBAC(ctx context.Context) (*rbacv3.RBAC, error) {
	data := &rbacv3.RBAC{
		Action:   rbacv3.RBAC_ALLOW,
		Policies: make(map[string]*rbacv3.Policy),
	}

	role1 := &rbacv3.Policy{
		Permissions: []*rbacv3.Permission{
			{
				Rule: &rbacv3.Permission_UrlPath{
					UrlPath: &matcherv3.PathMatcher{
						Rule: &matcherv3.PathMatcher_Path{
							Path: &matcherv3.StringMatcher{
								MatchPattern: &matcherv3.StringMatcher_Exact{
									Exact: "/",
								},
							},
						},
					},
				},
			},
		},
		Principals: []*rbacv3.Principal{
			{
				Identifier: &rbacv3.Principal_Any{
					Any: true,
				},
			},
		},
	}

	data.Policies["role-public"] = role1

	return data, nil
}

func (c *Client) defaultRego(ctx context.Context) (string, error) {
	testRego := `
package oneops.syncmi.v1

import future.keywords.if
import future.keywords.in

# import rego.v1

import data.oneops.syncmi.v1.action
import data.oneops.syncmi.v1.policies

default allow := false

allow if {
#	data.policies[input.appid][input.api_style]
#	input.pattern in data.policies[input.appid].pattern
#	# input.pattern in data.pattern
  policies["role-public"].permissions[0].url_path.path.exact == "/admin"
  input.attributes.request.http.method == "GET"
}
`
	return testRego, nil
}

func (c *Client) nonCommentLineLength(body []byte) (int, error) {
	if len(body) == 0 {
		return 0, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(body))
	nonCommentLines := 0

	for scanner.Scan() {
		line := scanner.Text()

		// 去除行首空白字符
		line = strings.TrimSpace(line)

		// 跳过空行和注释行
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// 非注释行计数
		nonCommentLines++
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return nonCommentLines, nil
}
