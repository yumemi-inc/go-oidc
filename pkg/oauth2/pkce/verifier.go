package pkce

import (
	"github.com/yumemi-inc/go-oidc/pkg/oauth2/errors"
)

var (
	ErrChallengeNotFound    = errors.New(errors.KindInvalidGrant, "PKCE challenge not found")
	ErrCodeVerifierMismatch = errors.New(errors.KindInvalidGrant, "code verifier mismatch")
)

type Verifier struct {
	CodeVerifier *string `form:"code_verifier,omitempty"`
}

func (v *Verifier) Validate(challenge *Challenge) *errors.Error {
	if v.CodeVerifier != nil && challenge == nil {
		return &ErrChallengeNotFound
	}

	if verifier := challenge.Transform(); *v.CodeVerifier != verifier {
		return &ErrCodeVerifierMismatch
	}

	return nil
}
