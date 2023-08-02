package main

import (
	"context"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
	"github.com/yumemi-inc/go-oidc/pkg/oidc"
)

type Client struct {
	ID           string
	Secret       string
	RedirectURIs []string
}

func (c Client) GetID() string {
	return c.ID
}

func (c Client) GetRedirectURIs() []string {
	return c.RedirectURIs
}

func (c Client) RequiresAuthentication() bool {
	return c.Secret != ""
}

func (c Client) Authenticate(_ context.Context, secret string) error {
	if !c.RequiresAuthentication() {
		return nil
	}

	if secret != c.Secret {
		return oauth2.ErrInvalidClientCredentials
	}

	return nil
}

func (c Client) AuthenticationMethod() oidc.ClientAuthenticationMethod {
	if c.RequiresAuthentication() {
		return oidc.ClientAuthenticationMethodClientSecretPOST
	}

	return oidc.ClientAuthenticationMethodNone
}
