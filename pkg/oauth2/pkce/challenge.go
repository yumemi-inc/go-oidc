package pkce

import (
	"crypto/sha256"
	"encoding/base64"

	"github.com/samber/lo"

	"github.com/yumemi-inc/go-oidc/pkg/oauth2/errors"
)

var (
	ErrPKCERequired               = errors.New(errors.KindInvalidRequest, "initiating PKCE required")
	ErrPKCEDenied                 = errors.New(errors.KindInvalidRequest, "initiating PKCE denied")
	ErrInvalidCodeChallenge       = errors.New(errors.KindInvalidRequest, "invalid code challenge")
	ErrInvalidCodeChallengeMethod = errors.New(errors.KindInvalidRequest, "invalid code challenge method")
)

type CodeChallengeMethod string

const (
	// CodeChallengeMethodPlain initiates PKCE with plain verifier.
	CodeChallengeMethodPlain CodeChallengeMethod = "plain"

	// CodeChallengeMethodS256 initiates PKCE with SHA-256 verifier.
	CodeChallengeMethodS256 CodeChallengeMethod = "S256"
)

type Challenge struct {
	CodeChallenge       *string              `form:"code_challenge,omitempty"`
	CodeChallengeMethod *CodeChallengeMethod `form:"code_challenge_method,omitempty"`
}

func (c *Challenge) Validate(mode Mode) error {
	if lo.Contains([]Mode{ModeRequiredStrict, ModeRequired}, mode) && c.CodeChallenge == nil {
		return ErrPKCERequired
	}

	codeChallengeMethod := CodeChallengeMethodPlain
	if c.CodeChallengeMethod != nil {
		codeChallengeMethod = *c.CodeChallengeMethod
	}

	if mode == ModeRequiredStrict && codeChallengeMethod != CodeChallengeMethodS256 {
		return ErrPKCERequired
	}

	if mode == ModeDenied {
		if c.CodeChallenge != nil {
			return ErrPKCEDenied
		}
	} else if c.CodeChallenge != nil {
		switch codeChallengeMethod {
		case CodeChallengeMethodPlain, CodeChallengeMethodS256:
			if len(*c.CodeChallenge) < 43 || len(*c.CodeChallenge) > 128 {
				return ErrInvalidCodeChallenge
			}

		default:
			return ErrInvalidCodeChallengeMethod
		}
	}

	return nil
}

func (c *Challenge) Transform() string {
	switch lo.FromPtr(c.CodeChallengeMethod) {
	case CodeChallengeMethodS256:
		digest := sha256.Sum256([]byte(lo.FromPtr(c.CodeChallenge)))

		return base64.URLEncoding.EncodeToString(digest[:])

	case CodeChallengeMethodPlain:
		fallthrough

	default:
		return lo.FromPtr(c.CodeChallenge)
	}
}
