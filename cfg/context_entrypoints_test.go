package cfg

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	pkgauth "github.com/grpc-kit/pkg/auth"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/resolver"
)

type requestContextKey struct{}

type contextKeySet struct {
	context context.Context
}

func (k *contextKeySet) VerifySignature(ctx context.Context, _ string) ([]byte, error) {
	k.context = ctx
	return nil, errors.New("test signature rejection")
}

type contextTestRegistry struct {
	context context.Context
}

func (*contextTestRegistry) Register(context.Context, string, string, string, int64) error {
	return nil
}

func (r *contextTestRegistry) Deregister(ctx context.Context) error {
	r.context = ctx
	return nil
}

func (r *contextTestRegistry) Build(resolver.Target, resolver.ClientConn, resolver.BuildOptions) (resolver.Resolver, error) {
	return r, nil
}

func (*contextTestRegistry) Scheme() string                        { return "test" }
func (*contextTestRegistry) Close()                                {}
func (*contextTestRegistry) ResolveNow(resolver.ResolveNowOptions) {}

func TestInitPropagatesContextToOIDCDiscovery(t *testing.T) {
	requestStarted := make(chan struct{})
	requestCanceled := make(chan struct{})
	var startOnce sync.Once
	var cancelOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		startOnce.Do(func() { close(requestStarted) })
		<-request.Context().Done()
		cancelOnce.Do(func() { close(requestCanceled) })
	}))
	t.Cleanup(server.Close)

	observablesEnabled := false
	config := &LocalConfig{
		Services: &ServicesConfig{ServiceCode: "test.v1"},
		Security: &SecurityConfig{
			Enable: true,
			Authentication: &Authentication{
				OIDCProvider: &OIDCProvider{Issuer: server.URL},
			},
		},
		Observables: &ObservablesConfig{Enable: &observablesEnabled},
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	if err := config.Init(ctx); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("OIDC discovery request did not start")
	}

	cancel()
	select {
	case <-requestCanceled:
	case <-time.After(5 * time.Second):
		t.Fatal("OIDC discovery request did not observe context cancellation")
	}
}

func TestSecurityHTTPHandlerPropagatesRequestContext(t *testing.T) {
	authClient, err := pkgauth.NewClient(t.Context(), &pkgauth.Config{PackageName: "test.policy"})
	if err != nil {
		t.Fatalf("auth.NewClient() error = %v", err)
	}
	enabled := true
	disabled := false
	security := &SecurityConfig{
		Enable:     true,
		authClient: authClient,
		Authorization: &Authorization{
			OPANative:      OPANative{Enabled: &enabled},
			OPAExternal:    OPAExternal{Enabled: &disabled},
			OPAEnvoyPlugin: OPAEnvoyPlugin{Enabled: &disabled},
		},
	}

	var handled bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		handled = true
		if got := request.Context().Value(requestContextKey{}); got != "request-context" {
			t.Errorf("request context value = %v, want request-context", got)
		}
		md, ok := metadata.FromIncomingContext(request.Context())
		if !ok {
			t.Fatal("authorization metadata missing from downstream request context")
		}
		if got := md.Get("grpc-kit-method"); len(got) != 1 || got[0] != http.MethodGet {
			t.Errorf("grpc-kit-method metadata = %v, want [%s]", got, http.MethodGet)
		}
	})
	request := httptest.NewRequest(http.MethodGet, "/secured", nil)
	request = request.WithContext(context.WithValue(request.Context(), requestContextKey{}, "request-context"))

	security.addHTTPHandler(next).ServeHTTP(httptest.NewRecorder(), request)
	if !handled {
		t.Fatal("authorized downstream handler was not called")
	}
}

func TestVerifyHTTPRequestPropagatesRequestContext(t *testing.T) {
	keySet := &contextKeySet{}
	security := &SecurityConfig{
		Enable: true,
		Authentication: &Authentication{
			OIDCProvider: &OIDCProvider{
				Issuer: "https://issuer.example",
				Config: &OIDCConfig{SupportedSigningAlgs: []string{"RS256"}},
			},
		},
	}
	security.setVerifier(oidc.NewVerifier("https://issuer.example", keySet, &oidc.Config{SkipClientIDCheck: true}))

	request := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	request = request.WithContext(context.WithValue(request.Context(), requestContextKey{}, "request-context"))
	request.Header.Set("Authorization", "Bearer eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJpc3N1ZXIifQ.AA")

	if err := security.VerifyHTTPRequest(request); err == nil {
		t.Fatal("VerifyHTTPRequest() error = nil, want signature rejection")
	}
	if keySet.context == nil {
		t.Fatal("OIDC verifier did not receive a context")
	}
	if got := keySet.context.Value(requestContextKey{}); got != "request-context" {
		t.Fatalf("OIDC verifier context value = %v, want request-context", got)
	}
}

func TestDeregisterPassesContextToRegistry(t *testing.T) {
	registry := &contextTestRegistry{}
	config := &LocalConfig{
		Discover:    &DiscoverConfig{},
		Observables: &ObservablesConfig{},
		srvdis:      registry,
	}
	ctx := context.WithValue(t.Context(), requestContextKey{}, "shutdown-context")

	if err := config.Deregister(ctx); err != nil {
		t.Fatalf("Deregister() error = %v", err)
	}
	if got := registry.context.Value(requestContextKey{}); got != "shutdown-context" {
		t.Fatalf("registry context value = %v, want shutdown-context", got)
	}
}

func TestInitStepsRejectCanceledContext(t *testing.T) {
	tests := []struct {
		name string
		init func(*LocalConfig, context.Context) error
	}{
		{name: "debugger", init: (*LocalConfig).initDebugger},
		{name: "services", init: (*LocalConfig).initServices},
		{name: "security", init: (*LocalConfig).initSecurity},
		{name: "database", init: (*LocalConfig).initDatabase},
		{name: "cachebox", init: (*LocalConfig).initCachebox},
		{name: "observables", init: (*LocalConfig).initObservables},
		{name: "cloud_events", init: (*LocalConfig).initCloudEvents},
		{name: "rpc_config", init: (*LocalConfig).initRPCConfig},
		{name: "objstore", init: (*LocalConfig).initObjstore},
		{name: "frontend", init: (*LocalConfig).initFrontend},
		{name: "automations", init: (*LocalConfig).initAutomations},
		{name: "ai_connector", init: (*LocalConfig).initAIConnector},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			if err := test.init(&LocalConfig{}, ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("init step error = %v, want context.Canceled", err)
			}
		})
	}
}
