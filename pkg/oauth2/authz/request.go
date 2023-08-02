package authz

import (
	"strings"

	"github.com/samber/lo"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
	"github.com/yumemi-inc/go-oidc/pkg/oauth2/errors"
	"github.com/yumemi-inc/go-oidc/pkg/oauth2/pkce"
)

var (
	ErrClientIDMismatch   = errors.New(errors.KindInvalidClient, "client ID mismatch")
	ErrInvalidRedirectURI = errors.New(errors.KindInvalidRequest, "invalid redirect URI")
	ErrInvalidScopeFormat = errors.New(errors.KindInvalidScope, "invalid scope format")
)

type ResponseType string

const (
	// ResponseTypeCode requires the provider to respond with authorization code, initiating Authorization Code Flow.
	ResponseTypeCode ResponseType = "code"

	// ResponseTypeToken requires the provider to respond with access token, initiating Implicit Flow.
	ResponseTypeToken ResponseType = "token"
)

type Request struct {
	ResponseType ResponseType `form:"response_type"`
	ClientID     string       `form:"client_id"`
	RedirectURI  *string      `form:"redirect_uri,omitempty"`
	Scope        *string      `form:"scope,omitempty"`
	State        *string      `form:"state,omitempty"`
	pkce.Challenge
}

type Response struct {
	Code  string  `form:"code"`
	State *string `form:"state,omitempty"`
}

func (r *Request) Scopes() []string {
	if r.Scope == nil {
		return nil
	}

	return strings.Split(*r.Scope, " ")
}

type RequestValidateOptions struct {
	PKCEMode pkce.Mode
}

func (r *Request) ValidateWithOptions(client oauth2.Client, options RequestValidateOptions) *errors.Error {
	if client.GetID() != r.ClientID {
		return &ErrClientIDMismatch
	}

	if r.RedirectURI != nil {
		if !lo.Contains(client.GetRedirectURIs(), *r.RedirectURI) {
			return &ErrInvalidRedirectURI
		}
	}

	if r.Scope != nil {
		for _, b := range []byte(*r.Scope) {
			if b < 0x21 || b == 0x22 || b == 0x5c || b > 0x7e {
				return &ErrInvalidScopeFormat
			}
		}
	}

	if err := r.Challenge.Validate(options.PKCEMode); err != nil {
		return err
	}

	return nil
}

func (r *Request) Validate(client oauth2.Client) *errors.Error {
	return r.ValidateWithOptions(
		client,
		RequestValidateOptions{
			PKCEMode: pkce.ModeAllowed,
		},
	)
}
