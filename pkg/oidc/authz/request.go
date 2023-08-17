package authz

import (
	"context"
	"io"
	"net/http"
	"net/url"

	"github.com/samber/lo"
	form "github.com/yumemi-inc/go-encoding-form"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
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

	ResponseMode *oidc.ResponseMode `form:"response_mode" json:"response_mode"`
	Claims       *ClaimRequests     `form:"claims" json:"claims"`
	Nonce        *string            `form:"nonce" json:"nonce"`
	Display      *oidc.Display      `form:"display" json:"display"`
	Prompt       *oidc.Prompt       `form:"prompt" json:"prompt"`
	MaxAge       *int64             `form:"max_age" json:"max_age"`
	UILocales    *string            `form:"ui_locales" json:"ui_locales"`
	IDTokenHint  *string            `form:"id_token_hint" json:"id_token_hint"`
	LoginHint    *string            `form:"login_hint" json:"login_hint"`
	ACRValues    *string            `form:"acr_values" json:"acr_values"`

	RequestJWT *string `form:"request" json:"-"`
	RequestURI *string `form:"request_uri" json:"-"`
}

func ReadRequest(r *http.Request) (*Request, error) {
	req := new(Request)
	if err := form.Denormalize(r.URL.Query(), req); err != nil {
		return nil, ErrMalformedRequest
	}

	return req, nil
}

// ExtractSignedJWT extracts request parameters from the signed JWT of a request object, superseding other parameters
// currently set. It also verifies the signed JWT, finding the appropriate key from the keychain.
func (r *Request) ExtractSignedJWT(jwtString string, keychain jwt.PublicKeychain) error {
	if r == nil {
		return nil
	}

	return jwt.Verify(jwtString, r, keychain)
}

// ExtractEncryptedJWT extracts request parameters from the encrypted JWT of a request object, superseding other
// parameters currently set. It also decrypts the encrypted JWT, finding the appropriate key from the keychain.
func (r *Request) ExtractEncryptedJWT(jwtString string, keychain jwt.Keychain) error {
	if r == nil {
		return nil
	}

	return jwt.Decrypt(jwtString, r, keychain)
}

// ExtractSignedRequestObject extracts request parameters from the signed JWT of a request object at `request`
// parameter, superseding other parameters currently set. If `request` parameter is not provided, it does nothing.
// It also verifies the signed JWT, finding the appropriate key from the keychain.
func (r *Request) ExtractSignedRequestObject(keychain jwt.PublicKeychain) error {
	if r == nil || r.RequestJWT == nil {
		return nil
	}

	return r.ExtractSignedJWT(*r.RequestJWT, keychain)
}

// ExtractEncryptedRequestObject extracts request parameters from the encrypted JWT of a request object at `request`
// parameter, superseding other parameters currently set. If `request` parameter is not provided, it does nothing.
// It also decrypts the encrypted JWT, finding the appropriate key from the keychain.
func (r *Request) ExtractEncryptedRequestObject(keychain jwt.Keychain) error {
	if r == nil || r.RequestJWT == nil {
		return nil
	}

	return r.ExtractEncryptedJWT(*r.RequestJWT, keychain)
}

// RetrieveJWT retrieves a signed or encrypted JWT of a request object from the URI specified at `request_uri`
// parameter.
func (r *Request) RetrieveJWT(ctx context.Context, transport http.RoundTripper) (string, error) {
	if r == nil || r.RequestURI == nil {
		return "", nil
	}

	u, err := url.Parse(*r.RequestURI)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}

	res, err := transport.RoundTrip(req)
	if err != nil {
		return "", err
	}

	defer func() {
		_ = res.Body.Close()
	}()

	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		return "", err
	}

	return string(bytes), nil
}

// RetrieveSignedRequestObject retrieves a signed JWT of a request object from the URI specified at `request_uri`
// parameter, and extracts it superseding other parameters currently set. If `request_uri` parameter is not provided, it
// does nothing. It also verifies the signed JWT, finding the appropriate key from the keychain.
func (r *Request) RetrieveSignedRequestObject(
	ctx context.Context,
	transport http.RoundTripper,
	keychain jwt.PublicKeychain,
) error {
	jwtString, err := r.RetrieveJWT(ctx, transport)
	if err != nil {
		return err
	} else if jwtString == "" {
		return nil
	}

	return r.ExtractSignedJWT(jwtString, keychain)
}

// RetrieveEncryptedRequestObject retrieves an encrypted JWT of a request object from the URI specified at `request_uri`
// parameter, and extracts it superseding other parameters currently set. If `request_uri` parameter is not provided, it
// does nothing. It also decrypts the encrypted JWT, finding the appropriate key from the keychain.
func (r *Request) RetrieveEncryptedRequestObject(
	ctx context.Context,
	transport http.RoundTripper,
	keychain jwt.Keychain,
) error {
	jwtString, err := r.RetrieveJWT(ctx, transport)
	if err != nil {
		return err
	} else if jwtString == "" {
		return nil
	}

	return r.ExtractEncryptedJWT(jwtString, keychain)
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
