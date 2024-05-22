package auth

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"

	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/config/rbac/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	matcherv3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/sdk"
	"github.com/open-policy-agent/opa/storage/inmem"
	"github.com/open-policy-agent/opa/util"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Client 认证鉴权客户端
type Client struct {
	logger *logrus.Entry
	config *Config

	envoy    *envoyProxy
	opaSDK   *sdk.OPA
	opaRego  rego.PreparedEvalQuery
	opaEnvoy authv3.AuthorizationClient
}

// NewClient 初始化实例
func NewClient(ctx context.Context, config *Config) (*Client, error) {
	var err error

	c := &Client{
		config: config,
		envoy:  &envoyProxy{},
		logger: logrus.NewEntry(logrus.New()),
	}

	if c.config.OPARego != nil {
		if err = c.initOPARego(ctx); err != nil {
			return nil, err
		}
	}

	if c.config.OPASDK != nil {
		if err = c.initOPASDK(ctx); err != nil {
			return nil, err
		}
	}

	if c.config.OPAEnvoy != nil {
		if err = c.initOPAEnvoy(ctx); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// initOPARego 初始化内置权限验证服务
func (c *Client) initOPARego(ctx context.Context) error {
	dataRego := c.config.OPARego.RegoBody
	dataRBAC := c.config.OPARego.DataBody

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
		rego.EnablePrintStatements(true),
	).PrepareForEval(ctx)
	if err != nil {
		return err
	}

	c.opaRego = query

	return nil
}

// initOPASDK 初始化 opa 连接外部统一授权服务
func (c *Client) initOPASDK(ctx context.Context) error {
	opaSDK, err := sdk.New(ctx,
		sdk.Options{
			ID:     c.config.PackageName,
			Config: strings.NewReader(c.config.OPASDK.Config),
		},
	)
	if err != nil {
		return err
	}

	c.opaSDK = opaSDK

	return nil
}

// initOPAEnvoy 初始化 opa 连接外部 envoy_ext_authz_grpc 授权服务
func (c *Client) initOPAEnvoy(ctx context.Context) error {
	addr := c.config.OPAEnvoy.GRPCAddress
	if addr == "" {
		addr = "127.0.0.1:9191"
	}

	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}

	c.opaEnvoy = authv3.NewAuthorizationClient(conn)

	return nil
}

// AuthMetadata 把 http 请求信息转换为 grpc 的 metadata 用于鉴权
func (c *Client) AuthMetadata(ctx context.Context, req *http.Request) context.Context {
	return c.envoy.extractHTTPHeader(ctx, req)
}

// Allow 是否满足策略允许访问
func (c *Client) Allow(ctx context.Context) (bool, error) {
	req, err := c.envoy.getCheckRequest(ctx)
	if err != nil {
		return false, err
	}

	input, err := c.envoy.requestToInput(req)
	if err != nil {
		return false, err
	}

	c.logger.Debugf("opa auth input: %s", string(util.MustMarshalJSON(input)))

	if c.config.OPARego != nil {
		var rs rego.ResultSet

		rs, err = c.opaRego.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			return false, err
		}

		if rs.Allowed() == false {
			return false, err
		}
	}

	if c.config.OPASDK != nil {
		var dr *sdk.DecisionResult

		dr, err = c.opaSDK.Decision(ctx,
			sdk.DecisionOptions{
				Path:  fmt.Sprintf("%v/allow", strings.Replace(c.config.PackageName, ".", "/", -1)),
				Input: input,
			},
		)
		if err != nil {
			return false, err
		}

		allow, ok := dr.Result.(bool)
		if !ok || !allow {
			return false, err
		}
	}

	if c.config.OPAEnvoy != nil {
		var resp *authv3.CheckResponse
		resp, err = c.opaEnvoy.Check(ctx, req)
		if err != nil {
			return false, err
		}
		if resp.GetStatus().Code != 0 {
			return false, err
		}
	}

	return true, nil
}

// SetLoggerOption 设置日志记录器
func (c *Client) SetLoggerOption(logger *logrus.Entry) *Client {
	if logger != nil {
		c.logger = logger
	}

	return c
}

// Close 关闭释放资源
func (c *Client) Close(ctx context.Context) {
	if c.opaSDK != nil {
		c.opaSDK.Stop(ctx)
	}
}

// https://pkg.go.dev/github.com/envoyproxy/go-control-plane@v0.12.0/envoy/config/rbac/v3#RBAC
func (c *Client) demoDataOPARBAC(ctx context.Context) (*rbacv3.RBAC, error) {
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
