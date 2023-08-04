package authz

import (
	"net/http"

	"github.com/samber/lo"
	form "github.com/yumemi-inc/go-encoding-form"

	oauth2 "github.com/yumemi-inc/go-oidc/pkg/oauth2/authz"
	"github.com/yumemi-inc/go-oidc/pkg/oidc"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/errors"
)

var (
	ErrClientIDMismatch        = oauth2.ErrClientIDMismatch
	ErrInvalidRedirectURI      = oauth2.ErrInvalidRedirectURI
	ErrInvalidScopeFormat      = oauth2.ErrInvalidScopeFormat
	ErrMalformedRequest        = oauth2.ErrMalformedRequest
	ErrUnsupportedResponseType = oauth2.ErrUnsupportedResponseType
	ErrOpenIDScopeRequired     = errors.New(errors.KindInvalidRequest, "openid scope is required")
)

type Request struct {
	oauth2.Request

	ResponseMode *oidc.ResponseMode `form:"response_mode"`
	Nonce        *string            `form:"nonce"`
	Display      *oidc.Display      `form:"display"`
	Prompt       *oidc.Prompt       `form:"prompt"`
	MaxAge       *int64             `form:"max_age"`
	UILocales    *string            `form:"ui_locales"`
	IDTokenHint  *string            `form:"id_token_hint"`
	LoginHint    *string            `form:"login_hint"`
	ACRValues    *string            `form:"acr_values"`
}

func ReadRequest(r *http.Request) (*Request, error) {
	req := new(Request)
	if err := form.Denormalize(r.URL.Query(), req); err != nil {
		return nil, ErrMalformedRequest
	}

	return req, nil
}

func (r *Request) Validate(client oidc.Client) error {
	// redirect_uri is optional in OAuth 2.0 but required in OIDC.
	if r.RedirectURI == nil || *r.RedirectURI == "" {
		return ErrInvalidRedirectURI
	}

	if err := r.Request.Validate(client); err != nil {
		return err
	}

	if !lo.Contains(r.Scopes(), oidc.ScopeOpenID) {
		return ErrOpenIDScopeRequired
	}

	return nil
}
