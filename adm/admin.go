package adm

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"golang.org/x/oauth2"
)

type AdminAPI struct {
}

func New() *AdminAPI {
	return &AdminAPI{}
}

func (a *AdminAPI) Handle() http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/admin/api/test", a.test).Methods("GET")
	r.HandleFunc("/admin/api/oidc/callback", a.oidcCallback).Methods("GET")

	return r
}

func (a *AdminAPI) test(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("hello"))
}

func (a *AdminAPI) oidcCallback(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, "http://127.0.0.1:8000/realms/default")
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
		ClientID:     "test1",
		ClientSecret: "testkey",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}

	oauth2Token, err := config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		w.Write([]byte(err.Error()))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		w.Write([]byte("no id token"))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	fmt.Println("raw id token: ", rawIDToken, ok, err)

	w.Write([]byte("oidc callback"))
}
