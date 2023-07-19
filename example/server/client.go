package main

import (
	"context"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
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

func (c Client) Authenticate(_ context.Context, secret string) error {
	if secret != c.Secret {
		return oauth2.ErrInvalidClientCredentials
	}

	return nil
}
