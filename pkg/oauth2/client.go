package oauth2

import (
	"context"
	"errors"
)

var ErrInvalidClientCredentials = errors.New("invalid client credentials")

type ClientType string

const (
	ClientTypeConfidential = "confidential"
	ClientTypePublic       = "public"
)

type Client interface {
	Type() ClientType
	GetID() string
	GetRedirectURIs() []string
	Authenticate(ctx context.Context, secret string) error
}

type ClientResolver func(ctx context.Context, id string) Client
