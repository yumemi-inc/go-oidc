package pkce

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/samber/lo"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2/errors"
)

var (
	ErrChallengeNotFound    = errors.New(errors.KindInvalidGrant, "PKCE challenge not found")
	ErrCodeVerifierMismatch = errors.New(errors.KindInvalidGrant, "code verifier mismatch")
)

type Verifier struct {
	CodeVerifier *string `form:"code_verifier,omitempty"`
}

func (v *Verifier) Transform(method CodeChallengeMethod) string {
	switch method {
	case CodeChallengeMethodS256:
		digest := sha256.Sum256([]byte(lo.FromPtr(v.CodeVerifier)))

		return base64.URLEncoding.EncodeToString(digest[:])

	case CodeChallengeMethodPlain:
		fallthrough

	default:
		return lo.FromPtr(v.CodeVerifier)
	}
}

func (v *Verifier) Validate(challenge *Challenge) error {
	if v.CodeVerifier != nil && challenge == nil {
		return ErrChallengeNotFound
	}

	if codeChallenge := v.Transform(lo.FromPtr(challenge.CodeChallengeMethod)); codeChallenge != lo.FromPtr(challenge.CodeChallenge) {
		return ErrCodeVerifierMismatch
	}

	return nil
}
