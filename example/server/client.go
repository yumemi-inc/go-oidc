package main

import (
	"context"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
	"github.com/yumemi-inc/go-oidc/pkg/oidc"
)

type Client struct {
	ID                     string
	Secret                 string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
}

func (c Client) Type() oauth2.ClientType {
	if c.Secret != "" {
		return oauth2.ClientTypeConfidential
	}

	return oauth2.ClientTypePublic
}

func (c Client) GetID() string {
	return c.ID
}

func (c Client) GetRedirectURIs() []string {
	return c.RedirectURIs
}

func (c Client) GetPostLogoutRedirectURIs() []string {
	return c.PostLogoutRedirectURIs
}

func (c Client) Authenticate(_ context.Context, secret string) error {
	if c.Type() != oauth2.ClientTypeConfidential {
		return nil
	}

	if secret != c.Secret {
		return oauth2.ErrInvalidClientCredentials
	}

	return nil
}

func (c Client) AuthenticationMethod() oidc.ClientAuthenticationMethod {
	if c.Type() == oauth2.ClientTypeConfidential {
		return oidc.ClientAuthenticationMethodClientSecretPOST
	}

	return oidc.ClientAuthenticationMethodNone
}
