package oidc

import (
	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
)

type Client interface {
	oauth2.Client
}
