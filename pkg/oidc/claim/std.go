package claim

import (
	"errors"
	"net/url"
	"time"

	"github.com/yumemi-inc/go-oidc/internal/typeconv"
)

const (
	SubMaxLength = 255
)

var (
	ErrIssScheme          = errors.New("scheme of issuer URL must be https")
	ErrIssQueryOrFragment = errors.New("issuer URL must not have query or fragment")
	ErrSubLength          = errors.New("subject must not exceed 255 ASCII characters in length")
)

// Iss is the identifier for the issuer.
type Iss url.URL

func NewIss(u url.URL) (*Iss, error) {
	if u.Scheme != "https" {
		return nil, ErrIssScheme
	}

	if u.RawQuery != "" || u.RawFragment != "" {
		return nil, ErrIssQueryOrFragment
	}

	return typeconv.Ptr(Iss(u)), nil
}

func IssFromStr(s string) (*Iss, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	return NewIss(*u)
}

// Sub is the subject identifier.
type Sub string

func NewSub(s string) (*Sub, error) {
	if len(s) > SubMaxLength {
		return nil, ErrSubLength
	}

	return typeconv.Ptr(Sub(s)), nil
}

// Aud is audience(s) that the token is intended for.
type Aud []string

func NewAud(s []string) *Aud {
	return typeconv.Ptr[Aud](s)
}

// Exp is the expiration time on or after which the token MUST NOT be accepted for processing.
type Exp time.Time

func NewExp(t time.Time) *Exp {
	return typeconv.Ptr(Exp(t))
}

func ExpFromInt64(i int64) *Exp {
	return NewExp(time.Unix(i, 0))
}

// Iat is the time at which the token was issued.
type Iat time.Time

func NewIat(t time.Time) *Iat {
	return typeconv.Ptr(Iat(t))
}

func IatFromInt64(i int64) *Iat {
	return NewIat(time.Unix(i, 0))
}

// AuthTime is the time when the end-user authentication occurred.
type AuthTime time.Time

func NewAuthTime(t time.Time) *AuthTime {
	return typeconv.Ptr(AuthTime(t))
}

func AuthTimeFromInt64(i int64) *AuthTime {
	return NewAuthTime(time.Unix(i, 0))
}

// Nonce is a string value used to associate a client session with the token, and to mitigate replay attacks.
type Nonce string

func NewNonce(s string) *Nonce {
	return typeconv.Ptr(Nonce(s))
}

// Acr is the authentication context class reference.
type Acr string

func NewAcr(s string) *Acr {
	return typeconv.Ptr(Acr(s))
}

// Amr is the authentication methods references.
type Amr []string

func NewAmr(s []string) *Amr {
	return typeconv.Ptr[Amr](s)
}

// Azp is the authorized party - the party to which the token was issued.
type Azp string

func NewAzp(s string) *Azp {
	return typeconv.Ptr(Azp(s))
}
