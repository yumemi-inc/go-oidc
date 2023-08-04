package endsession

import (
	"github.com/yumemi-inc/go-oidc/pkg/oidc"
)

// Client is a Relying Party that also supports RP-initiated logout. It is required to have post-logout redirect URIs to
// allow users redirecting back to the RP after logged out on OP.
type Client interface {
	oidc.Client

	GetPostLogoutRedirectURIs() []string
}
