package oidc

import (
	"context"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
)

type ClientAuthenticationMethod string

const (
	ClientAuthenticationMethodClientSecretBasic ClientAuthenticationMethod = "client_secret_basic"
	ClientAuthenticationMethodClientSecretPOST  ClientAuthenticationMethod = "client_secret_post"
	ClientAuthenticationMethodClientSecretJWT   ClientAuthenticationMethod = "client_secret_jwt"
	ClientAuthenticationMethodPrivateKeyJWT     ClientAuthenticationMethod = "private_key_jwt"
	ClientAuthenticationMethodNone              ClientAuthenticationMethod = "none"
)

type Client interface {
	oauth2.Client

	AuthenticationMethod() ClientAuthenticationMethod
}

type ClientResolver func(ctx context.Context, id string) Client
