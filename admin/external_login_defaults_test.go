package admin

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	adminv1 "github.com/grpc-kit/pkg/api/known/admin/v1"
	"github.com/grpc-kit/pkg/auth"
	"github.com/grpc-kit/pkg/crypto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestExternalLoginDefaultScopes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		values  []string
		want    string
		invalid bool
	}{
		{name: "nil"}, {name: "empty", values: []string{}},
		{name: "id", values: []string{"openid", auth.ScopeFederatedID}, want: "federated:id openid"},
		{name: "username", values: []string{"openid", auth.ScopeFederatedUsername}, want: "federated:username openid"},
		{name: "both and duplicates", values: []string{"openid", auth.ScopeFederatedUsername, auth.ScopeFederatedID, "openid"}, want: "federated:id federated:username openid"},
		{name: "unknown", values: []string{"openid", auth.ScopeFederatedID, "email"}, invalid: true},
		{name: "empty element", values: []string{"openid", auth.ScopeFederatedID, ""}, invalid: true},
		{name: "whitespace", values: []string{"openid", " federated:id"}, invalid: true},
		{name: "combined element", values: []string{"openid federated:id"}, invalid: true},
		{name: "no openid", values: []string{auth.ScopeFederatedID}, invalid: true},
		{name: "no federated scope", values: []string{"openid"}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := ContextWithExternalLoginDefaultScopes(t.Context(), tc.values)
			if len(tc.values) > 0 {
				tc.values[0] = "caller-mutated"
			}
			got, err := externalLoginDefaultScope(ctx)
			if tc.invalid {
				if status.Code(err) != codes.InvalidArgument {
					t.Fatalf("invalid scope accepted: %v", err)
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	ctx := ContextWithExternalLoginDefaultScopes(t.Context(), []string{"openid", auth.ScopeFederatedID})
	if got, err := externalLoginDefaultScope(ContextWithExternalLoginDefaultScopes(ctx, nil)); err != nil || got != "" {
		t.Fatal("empty list did not disable inherited defaults")
	}
}

func TestExternalLoginDefaultsIgnoreRemoteScopes(t *testing.T) {
	req := httptest.NewRequest("POST", "/auth/login?scope=openid+federated:id", nil)
	req.Header.Set("Grpc-Metadata-Scope", "openid federated:id")
	req.Header.Set("X-External-Login-Default-Scopes", "openid federated:id")
	httpCtx, err := runtime.AnnotateIncomingContext(t.Context(), runtime.NewServeMux(), req, "/admin.Auth/CreateAuthLogin")
	if err != nil {
		t.Fatal(err)
	}
	if scope, err := externalLoginDefaultScope(httpCtx); err != nil || scope != "" {
		t.Fatal("HTTP inputs enabled defaults")
	}
	metadataCtx := metadata.NewIncomingContext(t.Context(), metadata.Pairs("scope", "openid federated:id", "external_login_default_scopes", "openid federated:id"))
	if scope, err := externalLoginDefaultScope(metadataCtx); err != nil || scope != "" {
		t.Fatal("remote inputs enabled defaults")
	}
}

func TestExternalLoginDefaultClaimsValidationBeforeProjection(t *testing.T) {
	api := &KnownAdminAPI{}
	for _, raw := range []string{
		`{"connector_id":"ldap","user_id":"id","unknown":"x"}`,
		`{"connector_id":"ldap"}`, `{"connector_id":"ldap","user_id":""}`,
		`{"connector_id":"ldap","user_id":null}`,
		`{"connector_id":"ldap","user_id":"id","username":"Alice"}`,
	} {
		var snapshot auth.FederatedClaims
		if err := json.Unmarshal([]byte(raw), &snapshot); err != nil {
			t.Fatal(err)
		}
		issuance := AccessTokenIssuanceContext{ClientID: "login-client", Scope: "openid federated:id",
			source: &federatedSource{userID: 42, connectorID: "ldap", subject: "real-id"}}
		claims := &auth.AccessTokenClaims{CommonClaims: auth.CommonClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: "42"}, FederatedClaims: &snapshot}, ClientID: issuance.ClientID, Scope: issuance.Scope}
		if err := api.applyFederatedLoginClaims(t.Context(), claims, issuance); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("invalid original object accepted: %v", err)
		}
	}
	for _, source := range []*federatedSource{
		{userID: 41, connectorID: "ldap", subject: "id"},
		{userID: 42, connectorID: "", subject: "id"},
		{userID: 42, connectorID: strings.Repeat("x", 33), subject: "id"},
		{userID: 42, connectorID: "ldap", subject: "id", username: "bad\nname"},
	} {
		issuance := AccessTokenIssuanceContext{ClientID: "login-client", Scope: "openid federated:id", source: source}
		claims := &auth.AccessTokenClaims{CommonClaims: auth.CommonClaims{RegisteredClaims: jwt.RegisteredClaims{Subject: "42"}}, ClientID: issuance.ClientID, Scope: issuance.Scope}
		if err := api.applyFederatedLoginClaims(t.Context(), claims, issuance); status.Code(err) != codes.Unauthenticated {
			t.Fatalf("invalid source accepted after projection: %v", err)
		}
	}
	issuance := AccessTokenIssuanceContext{ClientID: "login-client", Scope: "openid federated:id"}
	claims := &auth.AccessTokenClaims{ClientID: issuance.ClientID, Scope: issuance.Scope}
	if err := api.applyFederatedLoginClaims(t.Context(), claims, issuance); err != nil || claims.FederatedClaims != nil {
		t.Fatal("missing source must be omitted")
	}
	priorID := "prior-id"
	claims.FederatedClaims = &auth.FederatedClaims{ConnectorID: "prior-provider", UserID: &priorID}
	if err := api.applyFederatedLoginClaims(t.Context(), claims, issuance); err != nil || claims.FederatedClaims != nil {
		t.Fatal("missing source must not retain a prior snapshot")
	}
	issuance.source = &federatedSource{userID: 42, connectorID: "ldap", username: "Alice"}
	claims.Subject = "42"
	if err := api.applyFederatedLoginClaims(t.Context(), claims, issuance); err != nil || claims.FederatedClaims != nil {
		t.Fatal("missing upstream subject must be omitted")
	}
	claims.Scope = "openid federated:username"
	if err := api.applyFederatedLoginClaims(t.Context(), claims, issuance); status.Code(err) != codes.Unauthenticated {
		t.Fatal("scope mismatch accepted")
	}
	claims.Scope, claims.ClientID = issuance.Scope, "other-client"
	if err := api.applyFederatedLoginClaims(t.Context(), claims, issuance); status.Code(err) != codes.Unauthenticated {
		t.Fatal("client mismatch accepted")
	}
}

func TestExternalLoginDefaultsStaticUsers(t *testing.T) {
	password := strings.Repeat("1", 64)
	userID := crypto.Username2UserID("static-user")
	static := &StaticUsers{{UserID: userID, Username: "static-user", PasswordHash: password, Roles: []string{"operator"}, Groups: []string{"team"}}}
	api := New(WithStaticUsers(static), WithOIDCProvider("", "login-client", ""))
	t.Cleanup(func() { close(api.mfaChallenges.stopGC) })
	ctx := ContextWithExternalLoginDefaultScopes(t.Context(), []string{"openid", auth.ScopeFederatedID})
	result, err := api.CreateAuthLogin(ctx, &adminv1.CreateAuthLoginRequest{Username: "static-user", PasswordHash: password, ExpiresIn: 123})
	if err != nil {
		t.Fatal(err)
	}
	claims := &auth.AccessTokenClaims{}
	if _, err := jwt.ParseWithClaims(result.AccessToken, claims, func(*jwt.Token) (any, error) { return []byte(password), nil }, jwt.WithValidMethods([]string{"HS256"})); err != nil {
		t.Fatal(err)
	}
	if claims.Scope != "" || claims.FederatedClaims != nil || claims.Subject != strconv.FormatInt(userID, 10) || claims.ClientID != "login-client" || claims.ExpiresAt.Sub(claims.IssuedAt.Time) != 123*time.Second || !reflect.DeepEqual(claims.Roles, []string{"operator"}) || !reflect.DeepEqual(claims.Groups, []string{"team"}) {
		t.Fatal("defaults changed static login")
	}
	ctx = ContextWithFederatedLoginAuthorization(ctx, FederatedLoginAuthorization{})
	if result, err := api.CreateAuthLogin(ctx, &adminv1.CreateAuthLoginRequest{Username: "static-user", PasswordHash: password}); err == nil || result.GetAccessToken() != "" {
		t.Fatal("empty explicit authorization fell back to defaults")
	}
}
