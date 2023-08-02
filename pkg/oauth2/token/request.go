package token

import (
	"context"
	"net/http"

	"github.com/samber/lo"

	"github.com/yumemi-inc/go-oidc/internal/typeconv"
	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
	"github.com/yumemi-inc/go-oidc/pkg/oauth2/authz"
	"github.com/yumemi-inc/go-oidc/pkg/oauth2/errors"
	"github.com/yumemi-inc/go-oidc/pkg/oauth2/pkce"
)

var (
	ErrClientAuthenticationFailed = errors.New(errors.KindUnauthorizedClient, "client authentication failed")
	ErrClientIDMismatch           = errors.New(errors.KindInvalidClient, "client ID mismatch")
	ErrMissingParameter           = errors.New(errors.KindInvalidRequest, "missing parameter")
	ErrRedirectURIMismatch        = errors.New(errors.KindInvalidGrant, "redirect URI mismatch")
	ErrUnsupportedGrantType       = errors.New(errors.KindUnsupportedGrantType, "unsupported grant type")
)

type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
)

type Request struct {
	GrantType    GrantType `form:"grant_type"`
	Code         *string   `from:"code,omitempty"`
	RedirectURI  *string   `form:"redirect_uri,omitempty"`
	ClientID     *string   `form:"client_id,omitempty"`
	ClientSecret *string   `form:"client_secret,omitempty"`
	pkce.Verifier
	// TODO: Assertions Framework
}

func (r *Request) Validate(
	ctx context.Context,
	httpRequest *http.Request,
	authzRequest *authz.Request,
	clientResolver oauth2.ClientResolver,
) *errors.Error {
	switch r.GrantType {
	case GrantTypeAuthorizationCode:
		if typeconv.IsEmptyOrNil(r.Code) || typeconv.IsEmptyOrNil(r.RedirectURI) || typeconv.IsEmptyOrNil(r.ClientID) {
			return &ErrMissingParameter
		}

		if authzRequest.RedirectURI != nil && lo.FromPtr(r.RedirectURI) != *authzRequest.RedirectURI {
			return &ErrRedirectURIMismatch
		}

		client := clientResolver(ctx, authzRequest.ClientID)
		if client == nil {
			return &ErrClientAuthenticationFailed
		}

		clientID, clientSecret, ok := httpRequest.BasicAuth()
		if ok {
			if clientID != client.GetID() || clientID != authzRequest.ClientID {
				return &ErrClientIDMismatch
			}

			if err := client.Authenticate(ctx, clientSecret); err != nil {
				return &ErrClientAuthenticationFailed
			}
		} else if r.ClientID != nil && r.ClientSecret != nil {
			if *r.ClientID != client.GetID() || *r.ClientID != authzRequest.ClientID {
				return &ErrClientIDMismatch
			}

			if err := client.Authenticate(ctx, lo.FromPtr(r.ClientSecret)); err != nil {
				return &ErrClientAuthenticationFailed
			}
		} else if client.RequiresAuthentication() {
			return &ErrClientAuthenticationFailed
		}

		if err := r.Verifier.Validate(&authzRequest.Challenge); err != nil {
			return err
		}
	default:
		return &ErrUnsupportedGrantType
	}

	return nil
}
