package cfg

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/grpc-kit/pkg/admin"
	"github.com/grpc-kit/pkg/crypto"
	"github.com/grpc-kit/pkg/rpc"
	"google.golang.org/grpc/metadata"
)

func TestInitSecurityRejectsInvalidStaticIDs(t *testing.T) {
	for _, enabled := range []bool{true, false} {
		for name, users := range map[string][]*BasicAuth{
			"reserved":   {{Username: "oneops", UserID: 110000}},
			"database":   {{Username: "oneops", UserID: 123456}},
			"wrong slot": {{Username: "oneops", UserID: 100000}},
			"collision":  {{Username: "review-service-155"}, {Username: "review-service-380"}},
			"duplicate":  {{Username: "oneops"}, {Username: "oneops"}},
			"nil":        {nil},
		} {
			t.Run(fmt.Sprintf("%s/enabled=%t", name, enabled), func(t *testing.T) {
				c := &LocalConfig{Security: &SecurityConfig{Enable: enabled, Authentication: &Authentication{HTTPUsers: users}}}
				if err := c.initSecurity(t.Context()); err == nil {
					t.Fatal("accepted invalid http_users")
				}
			})
		}
	}
}

func TestStaticUserIDWorksForBasicAndBearer(t *testing.T) {
	for _, explicit := range []int64{0, crypto.Username2UserID("oneops")} {
		const password = "test-only-static-password"
		c := &LocalConfig{Security: &SecurityConfig{Enable: true, Authentication: &Authentication{
			HTTPUsers: []*BasicAuth{{Username: "oneops", UserID: explicit, Password: password}},
		}}}
		if err := c.initSecurity(t.Context()); err != nil {
			t.Fatal(err)
		}
		ctx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("oneops:"+password))))
		ctx, err := c.authValidate()(ctx)
		if err != nil {
			t.Fatal(err)
		}
		want := crypto.Username2UserID("oneops")
		if got, ok := rpc.GetUserIDFromContext(ctx); !ok || got != want {
			t.Fatalf("basic identity = %d, present=%t, want %d", got, ok, want)
		}
		c.Security.Authentication.OIDCProvider = &OIDCProvider{Config: &OIDCConfig{
			SupportedSigningAlgs: []string{"HS256"}, SkipIssuerCheck: true, SkipClientIDCheck: true,
		}}
		user := admin.StaticUser{Username: "oneops", UserID: explicit, PasswordHash: crypto.SHA256([]byte(password))}
		token, err := user.GetAccessToken(3600, "test-client")
		if err != nil {
			t.Fatal(err)
		}
		claims, err := c.Security.verifyBearerToken(t.Context(), token)
		if err != nil || claims.GetMustUserID() != want {
			t.Fatalf("bearer identity = %d, err=%v", claims.GetMustUserID(), err)
		}
		c.Security.Authentication.HTTPUsers[0].UserID = 123456
		if _, err := c.Security.verifyBearerToken(t.Context(), token); err == nil {
			t.Fatal("verified token against invalid static configuration")
		}
	}
}
