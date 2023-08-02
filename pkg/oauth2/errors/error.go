package errors

import (
	"fmt"
)

type Kind string

const (
	// KindAccessDenied occurs when the resource owner or authorization server denied the request.
	KindAccessDenied Kind = "access_denied"

	// KindInvalidClient occurs when client authentication failed (e.g., unknown client, no client authentication
	// included, or unsupported authentication method).  The authorization server MAY return an HTTP 401 (Unauthorized)
	// status code to indicate which HTTP authentication schemes are supported.  If the client attempted to authenticate
	// via the "Authorization" request header field, the authorization server MUST respond with an HTTP 401
	// (Unauthorized) status code and include the "WWW-Authenticate" response header field matching the authentication
	// scheme used by the client.
	KindInvalidClient Kind = "invalid_client"

	// KindInvalidGrant occurs when the provided authorization grant (e.g., authorization code, resource owner
	// credentials) or refresh token is invalid, expired, revoked, does not match the redirection URI used in the
	// authorization request, or was issued to another client.
	KindInvalidGrant Kind = "invalid_grant"

	// KindInvalidRequest occurs when the request is missing a required parameter, includes an unsupported
	// parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than
	// one mechanism for authenticating the client, or is otherwise malformed.
	KindInvalidRequest Kind = "invalid_request"

	// KindInvalidScope occurs when the requested scope is invalid, unknown, malformed, or exceeds the scope
	// granted by the resource owner.
	KindInvalidScope Kind = "invalid_scope"

	// KindServerError occurs when the authorization server encountered an unexpected condition that prevented it
	// from fulfilling the request. (This error code is needed because a 500 Internal Server Error HTTP status code
	// cannot be returned to the client via an HTTP redirect.)
	KindServerError Kind = "server_error"

	// KindTemporarilyUnavailable occurs when the authorization server is currently unable to handle the request
	// due to a temporary overloading or maintenance of the server.  (This error code is needed because a 503 Service
	// Unavailable HTTP status code cannot be returned to the client via an HTTP redirect.)
	KindTemporarilyUnavailable Kind = "temporarily_unavailable"

	// KindUnauthorizedClient occurs when the authenticated client is not authorized to use this authorization
	// grant type.
	KindUnauthorizedClient Kind = "unauthorized_client"

	// KindUnsupportedGrantType occurs when the authorization grant type is not supported by the authorization
	// server.
	KindUnsupportedGrantType Kind = "unsupported_grant_type"

	// KindUnsupportedResponseType occurs when the authorization server does not support obtaining an authorization
	// code using this method.
	KindUnsupportedResponseType Kind = "unsupported_response_type"
)

type Error struct {
	Kind        Kind    `json:"error" form:"error"`
	Description string  `json:"error_description" form:"error_description"`
	URI         *string `json:"error_uri" form:"error_uri"`
	State       *string `json:"state" form:"state"`
}

func New(kind Kind, description string) Error {
	return Error{
		Kind:        kind,
		Description: description,
	}
}

func (e Error) WithState(state string) Error {
	e.State = &state

	return e
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Kind, e.Description)
}
