package token

import (
	"context"

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

type TokenType string

const (
	TokenTypeBearer TokenType = "bearer"
	TokenTypeMAC    TokenType = "mac"
)

type Request struct {
	GrantType    GrantType `form:"grant_type"`
	ClientID     string    `form:"client_id,omitempty"`
	ClientSecret *string   `form:"client_secret,omitempty"`
	Code         *string   `from:"code,omitempty"`
	RedirectURI  *string   `form:"redirect_uri,omitempty"`
	pkce.Verifier
}

type Response struct {
	AccessToken  string    `json:"access_token"`
	TokenType    TokenType `json:"token_type"`
	ExpiresIn    *uint     `json:"expires_in,omitempty"`
	RefreshToken *string   `json:"refresh_token,omitempty"`
	Scope        *string   `json:"scope,omitempty"`
}

func (r *Request) Validate(
	ctx context.Context,
	authzRequest *authz.Request,
	client oauth2.Client,
) *errors.Error {
	switch r.GrantType {
	case GrantTypeAuthorizationCode:
		if typeconv.IsEmptyOrNil(r.Code) || typeconv.IsEmptyOrNil(r.RedirectURI) || lo.IsEmpty(r.ClientID) {
			return &ErrMissingParameter
		}

		if r.ClientID != client.GetID() {
			return &ErrClientIDMismatch
		}

		if authzRequest.RedirectURI == nil || *r.RedirectURI != *authzRequest.RedirectURI {
			return &ErrRedirectURIMismatch
		}

		if err := client.Authenticate(ctx, lo.FromPtr(r.ClientSecret)); err != nil {
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
