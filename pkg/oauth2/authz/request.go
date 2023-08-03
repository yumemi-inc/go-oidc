package authz

import (
	"net/http"
	"strings"

	"github.com/samber/lo"
	form "github.com/yumemi-inc/go-encoding-form"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
	"github.com/yumemi-inc/go-oidc/pkg/oauth2/errors"
	"github.com/yumemi-inc/go-oidc/pkg/oauth2/pkce"
)

var (
	ErrClientIDMismatch        = errors.New(errors.KindInvalidClient, "client ID mismatch")
	ErrInvalidRedirectURI      = errors.New(errors.KindInvalidRequest, "invalid redirect URI")
	ErrInvalidScopeFormat      = errors.New(errors.KindInvalidScope, "invalid scope format")
	ErrMalformedRequest        = errors.New(errors.KindInvalidRequest, "malformed request")
	ErrUnsupportedResponseType = errors.New(errors.KindUnsupportedResponseType, "unsupported response type")
)

type Request struct {
	ResponseType oauth2.ResponseType `form:"response_type"`
	ClientID     string              `form:"client_id"`
	RedirectURI  *string             `form:"redirect_uri,omitempty"`
	Scope        *string             `form:"scope,omitempty"`
	State        *string             `form:"state,omitempty"`
	pkce.Challenge
}

func ReadRequest(r *http.Request) (*Request, error) {
	req := new(Request)
	if err := form.Denormalize(r.URL.Query(), req); err != nil {
		return nil, ErrMalformedRequest
	}

	return req, nil
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

func (r *Request) ValidateWithOptions(client oauth2.Client, options RequestValidateOptions) error {
	switch r.ResponseType {
	case oauth2.ResponseTypeCode, oauth2.ResponseTypeToken:
		// nothing to do

	default:
		return ErrUnsupportedResponseType
	}

	if client.GetID() != r.ClientID {
		return ErrClientIDMismatch
	}

	if r.RedirectURI != nil {
		if !lo.Contains(client.GetRedirectURIs(), *r.RedirectURI) {
			return ErrInvalidRedirectURI
		}
	}

	if r.Scope != nil {
		for _, b := range []byte(*r.Scope) {
			if b < 0x21 || b == 0x22 || b == 0x5c || b > 0x7e {
				return ErrInvalidScopeFormat
			}
		}
	}

	if err := r.Challenge.Validate(options.PKCEMode); err != nil {
		return err
	}

	return nil
}

func (r *Request) Validate(client oauth2.Client) error {
	return r.ValidateWithOptions(
		client,
		RequestValidateOptions{
			PKCEMode: pkce.ModeAllowed,
		},
	)
}
