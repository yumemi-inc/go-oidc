package token

import (
	"context"
	"net/http"
	"strings"

	"github.com/samber/lo"
	form "github.com/yumemi-inc/go-encoding-form"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
	"github.com/yumemi-inc/go-oidc/pkg/oauth2/authz"
	"github.com/yumemi-inc/go-oidc/pkg/oauth2/errors"
	"github.com/yumemi-inc/go-oidc/pkg/oauth2/pkce"
)

var (
	ErrClientAuthenticationFailed = errors.New(errors.KindUnauthorizedClient, "client authentication failed")
	ErrClientIDMismatch           = errors.New(errors.KindInvalidClient, "client ID mismatch")
	ErrInsufficientScopes         = errors.New(errors.KindInvalidGrant, "insufficient scopes")
	ErrMalformedRequest           = errors.New(errors.KindInvalidRequest, "malformed request")
	ErrMissingParameter           = errors.New(errors.KindInvalidRequest, "missing parameter")
	ErrRedirectURIMismatch        = errors.New(errors.KindInvalidGrant, "redirect URI mismatch")
	ErrUnsupportedGrantType       = errors.New(errors.KindUnsupportedGrantType, "unsupported grant type")
)

type GrantRequest interface {
	Type() oauth2.GrantType
}

type Request struct {
	GrantType    oauth2.GrantType `form:"grant_type"`
	ClientID     *string          `form:"client_id,omitempty"`
	ClientSecret *string          `form:"client_secret,omitempty"`
	// TODO: Assertions Framework
}

func (r *Request) AuthenticateClient(
	ctx context.Context,
	authzRequest *authz.Request,
	client oauth2.Client,
) error {
	if client.Type() == oauth2.ClientTypeConfidential {
		if r.ClientID == nil && r.ClientSecret == nil {
			return ErrClientAuthenticationFailed
		}

		if *r.ClientID != client.GetID() || *r.ClientID != authzRequest.ClientID {
			return ErrClientIDMismatch
		}

		if err := client.Authenticate(ctx, lo.FromPtr(r.ClientSecret)); err != nil {
			return ErrClientAuthenticationFailed
		}
	}

	return nil
}

type AuthorizationCodeGrantRequest struct {
	Request

	Code        string  `form:"code"`
	RedirectURI *string `form:"redirect_uri,omitempty"`
	pkce.Verifier
}

func (r *AuthorizationCodeGrantRequest) Type() oauth2.GrantType {
	return oauth2.GrantTypeAuthorizationCode
}

type RefreshTokenGrantRequest struct {
	Request

	RefreshToken string  `form:"refresh_token"`
	Scope        *string `form:"scope,omitempty"`
}

func (r *RefreshTokenGrantRequest) Type() oauth2.GrantType {
	return oauth2.GrantTypeRefreshToken
}

func ReadRequest(r *http.Request) (GrantRequest, error) {
	if err := r.ParseForm(); err != nil {
		return nil, ErrMalformedRequest
	}

	req := new(Request)
	if err := form.Denormalize(r.PostForm, req); err != nil {
		return nil, ErrMalformedRequest
	}

	clientID, clientSecret, ok := r.BasicAuth()
	if ok {
		req.ClientID = &clientID
		req.ClientSecret = &clientSecret
	}

	switch req.GrantType {
	case oauth2.GrantTypeAuthorizationCode:
		grantReq := new(AuthorizationCodeGrantRequest)
		if err := form.Denormalize(r.PostForm, grantReq); err != nil {
			return nil, ErrMalformedRequest
		}

		grantReq.Request = *req

		return grantReq, nil

	case oauth2.GrantTypeRefreshToken:
		req := &RefreshTokenGrantRequest{Request: *req}
		if err := form.Denormalize(r.PostForm, req); err != nil {
			return nil, ErrMalformedRequest
		}

		return req, nil
	}

	return nil, ErrUnsupportedGrantType
}

func (r *AuthorizationCodeGrantRequest) Validate(authzRequest *authz.Request) error {
	if lo.IsEmpty(r.Code) || r.RedirectURI == nil || *r.RedirectURI == "" {
		return ErrMissingParameter
	}

	if authzRequest.RedirectURI != nil && lo.FromPtr(r.RedirectURI) != *authzRequest.RedirectURI {
		return ErrRedirectURIMismatch
	}

	if err := r.Verifier.Validate(&authzRequest.Challenge); err != nil {
		return err
	}

	return nil
}

func (r *RefreshTokenGrantRequest) Scopes() []string {
	if r.Scope == nil {
		return nil
	}

	return strings.Split(*r.Scope, " ")
}

func (r *RefreshTokenGrantRequest) Validate(authzRequest *authz.Request) error {
	if lo.IsEmpty(r.RefreshToken) {
		return ErrMissingParameter
	}

	if !lo.Every(authzRequest.Scopes(), r.Scopes()) {
		return ErrInsufficientScopes
	}

	return nil
}
