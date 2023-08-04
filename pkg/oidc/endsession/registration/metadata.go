package registration

// Metadata is additional metadata on dynamic client registration for RP-initiated logout.
type Metadata struct {
	// PostLogoutRedirectURIs is Array of URLs supplied by the RP to which it MAY request that the End-User's User Agent
	// be redirected using the post_logout_redirect_uri parameter after a logout has been performed. These URLs SHOULD
	// use the https scheme and MAY contain port, path, and query parameter components; however, they MAY use the http
	// scheme, provided that the Client Type is confidential, as defined in Section 2.1 of OAuth 2.0, and provided the
	// OP allows the use of http RP URIs.
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
}
