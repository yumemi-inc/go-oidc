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

var claimScopes = []string{oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeAddress, oidc.ScopePhone}

type ClaimRequest struct {
	Essential *bool `json:"essential,omitempty"`
	Value     any   `json:"value,omitempty"`
	Values    []any `json:"values,omitempty"`
}

type ClaimRequests struct {
	Userinfo map[string]*ClaimRequest `json:"userinfo,omitempty"`
	IDToken  map[string]*ClaimRequest `json:"id_token,omitempty"`
}

type Request struct {
	oauth2.Request

	ResponseMode *oidc.ResponseMode `form:"response_mode"`
	Claims       *ClaimRequests     `form:"claims"`
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

// RequestedUserinfoClaims returns a set of claim names that the client requested by claims parameter or scopes.
// The claims requested by scopes are included only if the response_type is NOT id_token.
func (r *Request) RequestedUserinfoClaims() []string {
	claims := make([]string, 0)

	if r.ResponseType != oidc.ResponseTypeIDToken {
		claims = append(claims, lo.Intersect(claimScopes, r.Scopes())...)
	}

	for c := range r.Claims.Userinfo {
		claims = append(claims, c)
	}

	return lo.Uniq(claims)
}

// RequestedIDTokenClaims returns a set of claim names that the client requested by claims parameter or scopes.
// The claims requested by scopes are included only if the response_type is id_token.
func (r *Request) RequestedIDTokenClaims() []string {
	claims := make([]string, 0)

	if r.ResponseType == oidc.ResponseTypeIDToken {
		claims = append(claims, lo.Intersect(claimScopes, r.Scopes())...)
	}

	for c := range r.Claims.IDToken {
		claims = append(claims, c)
	}

	return lo.Uniq(claims)
}

// RequestedClaims returns a set of all claim names that the client requested by claims parameter or scopes.
func (r *Request) RequestedClaims() []string {
	return lo.Uniq(append(r.RequestedUserinfoClaims(), r.RequestedIDTokenClaims()...))
}
