package oauth2

type ResponseType string

const (
	// ResponseTypeCode requires the provider to respond with authorization code, initiating Authorization Code Flow.
	ResponseTypeCode ResponseType = "code"

	// ResponseTypeToken requires the provider to respond with access token, initiating Implicit Flow.
	ResponseTypeToken ResponseType = "token"
)

type GrantType string

const (
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypeRefreshToken      GrantType = "refresh_token"
)
