package admin

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/grpc-kit/pkg/lion"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

// KnownAdminAPI xx
type KnownAdminAPI struct {
	config *config
	logger *logrus.Entry
}

// New xx
func New(opts ...Options) *KnownAdminAPI {
	c := &config{}

	for _, opt := range opts {
		opt(c)
	}

	// TODO; 默认值设置
	if c.logger == nil {
		c.logger = logrus.NewEntry(logrus.New())
	}

	return &KnownAdminAPI{
		config: c,
		logger: c.logger,
	}
}

/*
func (a *AdminAPI) Handle() http.Handler {
	r := mux.NewRouter()

	prefix := a.config.prefix

	r.HandleFunc(path.Join(prefix, "/v1/test"), a.test).Methods("GET")
	r.HandleFunc(path.Join(prefix, "/v1/test"), a.test).Methods("POST")
	r.HandleFunc(path.Join(prefix, "/v1/oidc/callback"), a.oidcCallback).Methods("GET")

	// /builtin/admin/api/v1/auth/login
	// /builtin/admin/api/v1/auth/logout
	// /builtin/admin/api/v1/auth/callback/oidc
	// /builtin/admin/api/v1/auth/callback/wechat
	// /builtin/admin/api/v1/auth/callback/google
	r.HandleFunc(path.Join(prefix, "/v1/auth/local/login"), a.authLogin).Methods("POST")

	return r
}
*/

func (a *KnownAdminAPI) GetLionClient() (*lion.Client, error) {
	if a.config == nil || a.config.db == nil {
		return nil, fmt.Errorf("not found database client")
	}

	return a.config.db, nil
}

func (a *KnownAdminAPI) test(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	// { code: 0, data: { token: 'xxx' }, message: '登录成功' }
	w.Write([]byte(`{ "code": 0, "data": { "token": "xxx" }, "message": "登录成功" }`))
}

func (a *KnownAdminAPI) oidcCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, a.config.provider)
	if err != nil {
		log.Fatal(err)
	}

	/*
		oidcConfig := &oidc.Config{
			ClientID: "test1",
		}
		verifier := provider.Verifier(oidcConfig)
	*/

	config := oauth2.Config{
		ClientID:     a.config.clientID,
		ClientSecret: a.config.clientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		RedirectURL:  "http://127.0.0.1:8080/admin/builtin/api/v1/oidc/callback",
	}

	oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(err.Error()))
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("no id token"))
		return
	}

	fmt.Println("raw id token: ", rawIDToken, ok, err)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("oidc callback"))
}
