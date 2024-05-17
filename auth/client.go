package auth

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/sdk"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
	"google.golang.org/grpc/metadata"
)

// Client xx
type Client struct {
	config *Config

	opaSDK  *sdk.OPA
	opaRego rego.PreparedEvalQuery
}

// NewClient xx
func NewClient(config *Config) (*Client, error) {
	c := &Client{
		config: config,
	}

	return c, nil
}

// InitOPARego xx
func (c *Client) InitOPARego(ctx context.Context, dataRego, dataFile []byte) error {
	var jsonData map[string]interface{}
	if err := util.Unmarshal(dataFile, &jsonData); err != nil {
		return err
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

func (c *Client) Decision(ctx context.Context) (*sdk.DecisionResult, error) {
	input, err := c.opaUserInputData(ctx)
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
	input, err := c.opaUserInputData(ctx)
	if err != nil {
		return nil, err
	}

	return c.opaRego.Eval(ctx, rego.EvalInput(input))
}

// Close xx
func (c *Client) Close() {

}

// 用户输入数据
// 转换为兼容 envoy 数据格式
// https://pkg.go.dev/github.com/envoyproxy/go-control-plane@v0.12.0/envoy/service/auth/v3#CheckRequest
func (c *Client) opaUserInputData(ctx context.Context) (*authv3.CheckRequest, error) {
	input := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Headers: map[string]string{
						"x-forwarded-proto": "https",
					},
					Method: "GET",
				},
			},
		},
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		for k, v := range md {
			fmt.Println("k:", k, "v:", v)
		}
	}

	return input, nil
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
