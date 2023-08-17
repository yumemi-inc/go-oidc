package endsession

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/samber/lo"
	form "github.com/yumemi-inc/go-encoding-form"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
	"github.com/yumemi-inc/go-oidc/pkg/oidc/claim"
)

var (
	ErrClientNotProvided            = errors.New("client ID specified but not provided")
	ErrInvalidAudience              = errors.New("invalid audience; ID token is not for the provided client")
	ErrInvalidPostLogoutRedirectURI = errors.New("invalid post logout redirect URI")
)

type Request struct {
	// IDTokenHint is ID Token previously issued by the OP to the RP passed to the Logout Endpoint as a hint about the
	// End-User's current authenticated session with the Client. This is used as an indication of the identity of the
	// End-User that the RP is requesting be logged out by the OP.
	IDTokenHint *string `form:"id_token_hint,omitempty"`

	// LogoutHint is hint to the Authorization Server about the End-User that is logging out. The value and meaning of
	// this parameter is left up to the OP's discretion. For instance, the value might contain an email address, phone
	// number, username, or session identifier pertaining to the RP's session with the OP for the End-User. (This
	// parameter is intended to be analogous to the login_hint parameter defined in Section 3.1.2.1 of OpenID Connect
	// Core 1.0 that is used in Authentication Requests; whereas, logout_hint is used in RP-Initiated Logout Requests.)
	LogoutHint *string `form:"logout_hint,omitempty"`

	// ClientID is OAuth 2.0 Client Identifier valid at the Authorization Server. When both client_id and id_token_hint
	// are present, the OP MUST verify that the Client Identifier matches the one used when issuing the ID Token. The
	// most common use case for this parameter is to specify the Client Identifier when post_logout_redirect_uri is used
	// but id_token_hint is not. Another use is for symmetrically encrypted ID Tokens used as id_token_hint values that
	// require the Client Identifier to be specified by other means, so that the ID Tokens can be decrypted by the OP.
	ClientID *string `form:"client_id,omitempty"`

	// PostLogoutRedirectURI is URI to which the RP is requesting that the End-User's User Agent be redirected after a
	// logout has been performed. This URI SHOULD use the https scheme and MAY contain port, path, and query parameter
	// components; however, it MAY use the http scheme, provided that the Client Type is confidential, as defined in
	// Section 2.1 of OAuth 2.0, and provided the OP allows the use of http RP URIs. The URI MAY use an alternate
	// scheme, such as one that is intended to identify a callback into a native application. The value MUST have been
	// previously registered with the OP, either using the post_logout_redirect_uris Registration parameter or via
	// another mechanism. An id_token_hint is also RECOMMENDED when this parameter is included.
	PostLogoutRedirectURI *string `form:"post_logout_redirect_uri,omitempty"`

	// State is opaque value used by the RP to maintain state between the logout request and the callback to the
	// endpoint specified by the post_logout_redirect_uri parameter. If included in the logout request, the OP passes
	// this value back to the RP using the state parameter when redirecting the User Agent back to the RP.
	State *string `form:"state,omitempty"`

	// UILocales are End-User's preferred languages and scripts for the user interface, represented as a space-separated
	// list of BCP47 language tag values, ordered by preference. For instance, the value "fr-CA fr en" represents a
	// preference for French as spoken in Canada, then French (without a region designation), followed by English
	// (without a region designation). An error SHOULD NOT result if some or all of the requested locales are not
	// supported by the OpenID Provider.
	UILocales *string `form:"ui_locales,omitempty"`

	claims claim.Claims
}

// ReadRequest reads RP-initiated logout request from the HTTP request.
func ReadRequest(r *http.Request) (*Request, error) {
	var values url.Values
	if r.Method == http.MethodGet {
		values = r.URL.Query()
	} else {
		values = r.PostForm
	}

	req := new(Request)
	if err := form.Denormalize(values, req); err != nil {
		return nil, err
	}

	return req, nil
}

// Claims decodes and verifies claims in the ID token using the keychain.
func (r *Request) Claims(keychain jwt.PublicKeychain) (claim.Claims, error) {
	if r.claims != nil {
		return r.claims, nil
	}

	if r.IDTokenHint == nil {
		return nil, nil
	}

	claims, err := claim.ClaimsFromSignedJWT(*r.IDTokenHint, keychain)
	if err != nil {
		return nil, err
	}

	r.claims = claims

	return claims, nil
}

// Validate validates the RP-initiated logout request. OP can ignore the error(s) and continue logging out, but the
// request that failed to validate MUST NOT be used. Also, OP MUST NOT perform post-logout redirection when any error
// detected on validation.
func (r *Request) Validate(client Client, keychain jwt.PublicKeychain) error {
	if r.ClientID == nil {
		return nil
	}

	if client == nil {
		return ErrClientNotProvided
	}

	if r.PostLogoutRedirectURI != nil {
		if !lo.Contains(client.GetPostLogoutRedirectURIs(), *r.PostLogoutRedirectURI) {
			return ErrInvalidPostLogoutRedirectURI
		}
	}

	if r.IDTokenHint != nil {
		claims, err := r.Claims(keychain)
		if err != nil {
			return err
		}

		aud, ok := claims["aud"].(claim.Aud)
		if !ok {
			return ErrInvalidAudience
		}

		if !aud.Contains(client.GetID()) {
			return ErrInvalidAudience
		}
	}

	return nil
}
