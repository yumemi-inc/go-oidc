package token

import (
	"context"
	"net/http"

	oauth2 "github.com/yumemi-inc/go-oidc/pkg/oauth2/token"
	"github.com/yumemi-inc/go-oidc/pkg/oidc"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/authz"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/errors"
)

var (
	ErrUnsupportedClientAuthenticationMethod = errors.New(
		errors.KindUnauthorizedClient,
		"unsupported client authentication method",
	)
	ErrUnsupportedGrantType = oauth2.ErrUnsupportedGrantType
)

type GrantRequest interface {
	oauth2.GrantRequest
}

type Request struct {
	oauth2.Request
}

type AuthorizationCodeGrantRequest struct {
	oauth2.AuthorizationCodeGrantRequest
}

type RefreshTokenGrantRequest struct {
	oauth2.RefreshTokenGrantRequest
}

func ReadRequest(r *http.Request) (GrantRequest, error) {
	req, err := oauth2.ReadRequest(r)
	if err != nil {
		return nil, err
	}

	switch req := req.(type) {
	case *oauth2.AuthorizationCodeGrantRequest:
		return &AuthorizationCodeGrantRequest{
			AuthorizationCodeGrantRequest: *req,
		}, nil

	case *oauth2.RefreshTokenGrantRequest:
		return &RefreshTokenGrantRequest{
			RefreshTokenGrantRequest: *req,
		}, nil
	}

	return nil, ErrUnsupportedGrantType
}

func (r *Request) AuthenticateClient(
	ctx context.Context,
	authzRequest *authz.Request,
	client oidc.Client,
) error {
	switch client.AuthenticationMethod() {
	case oidc.ClientAuthenticationMethodClientSecretBasic, oidc.ClientAuthenticationMethodClientSecretPOST:
		if err := r.Request.AuthenticateClient(ctx, &authzRequest.Request, client); err != nil {
			return err
		}

	case oidc.ClientAuthenticationMethodNone:
		// nothing to do

	default:
		return ErrUnsupportedClientAuthenticationMethod
	}

	return nil
}

func (r *AuthorizationCodeGrantRequest) Validate(authzRequest *authz.Request) error {
	return r.AuthorizationCodeGrantRequest.Validate(&authzRequest.Request)
}

func (r *RefreshTokenGrantRequest) Validate(authzRequest *authz.Request) error {
	return r.RefreshTokenGrantRequest.Validate(&authzRequest.Request)
}
