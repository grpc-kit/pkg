package adm

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"path"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
)

type AdminAPI struct {
	// api 接口前缀
	prefix string
	// oidc 认证域名
	provider string
	// oidc 客户端ID
	clientID string
	// oidc 客户端密钥
	clientSecret string
}

func New(prefix, provider, clientID, clientSecret string) *AdminAPI {
	return &AdminAPI{
		prefix:       prefix,
		provider:     provider,
		clientID:     clientID,
		clientSecret: clientSecret,
	}
}

func (a *AdminAPI) Handle() http.Handler {
	r := mux.NewRouter()

	r.HandleFunc(path.Join(a.prefix, "/v1/test"), a.test).Methods("GET")
	r.HandleFunc(path.Join(a.prefix, "/v1/oidc/callback"), a.oidcCallback).Methods("GET")

	return r
}

func (a *AdminAPI) test(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("hello"))
}

func (a *AdminAPI) oidcCallback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, a.provider)
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
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
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
