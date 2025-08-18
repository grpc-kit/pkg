package admin

import (
	"context"
	"github.com/grpc-kit/pkg/crypto"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/grpc-kit/pkg/lion"
	"github.com/grpc-kit/pkg/lion/authproviders"
)

type socialUsers struct {
	db *lion.Client

	aesKey       []byte
	ProviderName string
	AuthProvider *lion.AuthProviders
}

func newSocialUsers(ctx context.Context, aesKey []byte, db *lion.Client, providerName string) (*socialUsers, error) {
	ap, err := db.AuthProviders.Query().
		Select(
			"name",
			"type",
			"enabled",
			"client_id",
			"client_secret_encrypted",
			"issuer",
			"authorization_endpoint",
			"scopes",
			"redirect_uri",
		).
		Where(
			authproviders.NameEQ(providerName),
		).Only(ctx)
	if err != nil {
		return nil, err
	}

	s := &socialUsers{
		db:           db,
		aesKey:       aesKey,
		ProviderName: providerName,
		AuthProvider: ap,
	}

	return s, nil
}

func (s *socialUsers) oauth2Exchange(ctx context.Context, code string) (*oauth2.Token, error) {
	op, err := oidc.NewProvider(ctx, s.AuthProvider.Issuer)
	if err != nil {
		return nil, err
	}

	var clientSecret []byte
	clientSecret, err = crypto.DecryptAES(s.aesKey, s.AuthProvider.ClientSecretEncrypted)
	if err != nil {
		return nil, err
	}

	oauth2Config := oauth2.Config{
		ClientID:     s.AuthProvider.ClientID,
		ClientSecret: string(clientSecret),
		Endpoint:     op.Endpoint(),
		Scopes:       strings.Split(s.AuthProvider.Scopes, " "),
		RedirectURL:  s.AuthProvider.RedirectURI,
	}

	token, err := oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}

	return token, nil
}
