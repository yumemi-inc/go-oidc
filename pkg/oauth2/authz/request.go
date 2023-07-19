package authz

import (
	"errors"
	"strings"

	"github.com/samber/lo"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2"
)

var (
	ErrClientIDMismatch           = errors.New("client ID mismatch")
	ErrInvalidRedirectURI         = errors.New("invalid redirect URI")
	ErrInvalidScopeFormat         = errors.New("invalid scope format")
	ErrPKCERequired               = errors.New("initiating PKCE required")
	ErrPKCEDenied                 = errors.New("initiating PKCE denied")
	ErrInvalidCodeChallenge       = errors.New("invalid code challenge")
	ErrInvalidCodeChallengeMethod = errors.New("invalid code challenge method")
)

type ResponseType string

const (
	// ResponseTypeCode requires the provider to respond with authorization code, initiating Authorization Code Flow.
	ResponseTypeCode ResponseType = "code"

	// ResponseTypeToken requires the provider to respond with access token, initiating Implicit Flow.
	ResponseTypeToken ResponseType = "token"
)

type CodeChallengeMethod string

const (
	// CodeChallengeMethodPlain initiates PKCE with plain verifier.
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"

	// CodeChallengeMethodS256 initiates PKCE with SHA-256 verifier.
	CodeChallengeMethodS256 CodeChallengeMethod = "S256"
)

type Request struct {
	ResponseType        ResponseType         `form:"response_type"`
	ClientID            string               `form:"client_id"`
	RedirectURI         *string              `form:"redirect_uri,omitempty"`
	Scope               *string              `form:"scope,omitempty"`
	State               *string              `form:"state,omitempty"`
	CodeChallenge       *string              `form:"code_challenge,omitempty"`
	CodeChallengeMethod *CodeChallengeMethod `form:"code_challenge_method,omitempty"`
}

type Response struct {
	Code  string  `form:"code"`
	State *string `form:"state,omitempty"`
}

func (r *Request) Scopes() []string {
	if r.Scope == nil {
		return nil
	}

	return strings.Split(*r.Scope, " ")
}

type PKCEMode int

const (
	// PKCEModeRequiredStrict requires the client to initiate PKCE with S256 challenge method.
	PKCEModeRequiredStrict PKCEMode = iota

	// PKCEModeRequired requires the client to initiate PKCE.
	PKCEModeRequired

	// PKCEModeAllowed allows the client to initiate PKCE, but not required.
	PKCEModeAllowed

	// PKCEModeDenied denies any request initiating PKCE.
	PKCEModeDenied
)

type RequestValidateOptions struct {
	PKCEMode PKCEMode
}

func (r *Request) ValidateWithOptions(client oauth2.Client, options RequestValidateOptions) error {
	if client.GetID() != r.ClientID {
		return ErrClientIDMismatch
	}

	if lo.Contains([]PKCEMode{PKCEModeRequiredStrict, PKCEModeRequired}, options.PKCEMode) && r.CodeChallenge == nil {
		return ErrPKCERequired
	}

	codeChallengeMethod := CodeChallengeMethodPlain
	if r.CodeChallengeMethod != nil {
		codeChallengeMethod = *r.CodeChallengeMethod
	}

	if options.PKCEMode == PKCEModeRequiredStrict && codeChallengeMethod != CodeChallengeMethodS256 {
		return ErrPKCERequired
	}

	if options.PKCEMode == PKCEModeDenied {
		if r.CodeChallenge != nil {
			return ErrPKCEDenied
		}
	} else if r.CodeChallenge != nil {
		switch codeChallengeMethod {
		case CodeChallengeMethodPlain, CodeChallengeMethodS256:
			if len(*r.CodeChallenge) < 43 || len(*r.CodeChallenge) > 128 {
				return ErrInvalidCodeChallenge
			}

		default:
			return ErrInvalidCodeChallengeMethod
		}
	}

	if r.RedirectURI != nil {
		if !lo.Contains(client.GetRedirectURIs(), *r.RedirectURI) {
			return ErrInvalidRedirectURI
		}
	}

	if r.Scope != nil {
		for _, b := range []byte(*r.Scope) {
			if b < 0x21 || b == 0x22 || b == 0x5c || b > 0x7e {
				return ErrInvalidScopeFormat
			}
		}
	}

	return nil
}

func (r *Request) Validate(client oauth2.Client) error {
	return r.ValidateWithOptions(
		client,
		RequestValidateOptions{
			PKCEMode: PKCEModeAllowed,
		},
	)
}
