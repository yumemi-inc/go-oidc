package oauth2

import (
	"context"
	"errors"
)

var ErrInvalidClientCredentials = errors.New("invalid client credentials")

type Client interface {
	GetID() string
	GetRedirectURIs() []string
	Authenticate(ctx context.Context, secret string) error
}
