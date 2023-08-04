package claim

import (
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/samber/lo"
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

	return lo.ToPtr(Iss(u)), nil
}

func IssFromStr(s string) (*Iss, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}

	return NewIss(*u)
}

func (c Iss) ClaimName() string {
	return "iss"
}

func (c Iss) String() string {
	u := url.URL(c)

	return u.String()
}

func (c Iss) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.String())
}

func (c *Iss) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}

	p, err := IssFromStr(s)
	if err != nil {
		return err
	}

	*c = *p

	return nil
}

// Sub is the subject identifier.
type Sub string

func NewSub(s string) (*Sub, error) {
	if len(s) > SubMaxLength {
		return nil, ErrSubLength
	}

	return lo.ToPtr(Sub(s)), nil
}

func (c Sub) ClaimName() string {
	return "sub"
}

// Aud is audience(s) that the token is intended for.
type Aud []string

func NewAud(s []string) *Aud {
	return lo.ToPtr[Aud](s)
}

func (c Aud) Contains(audience string) bool {
	for _, a := range c {
		if a == audience {
			return true
		}
	}

	return false
}

func (c Aud) ClaimName() string {
	return "aud"
}

// Exp is the expiration time on or after which the token MUST NOT be accepted for processing.
type Exp time.Time

func NewExp(t time.Time) *Exp {
	return lo.ToPtr(Exp(t))
}

func ExpFromInt64(i int64) *Exp {
	return NewExp(time.Unix(i, 0))
}

func (c Exp) ClaimName() string {
	return "exp"
}

// Iat is the time at which the token was issued.
type Iat time.Time

func NewIat(t time.Time) *Iat {
	return lo.ToPtr(Iat(t))
}

func IatFromInt64(i int64) *Iat {
	return NewIat(time.Unix(i, 0))
}

func (c Iat) ClaimName() string {
	return "iat"
}

// AuthTime is the time when the end-user authentication occurred.
type AuthTime time.Time

func NewAuthTime(t time.Time) *AuthTime {
	return lo.ToPtr(AuthTime(t))
}

func AuthTimeFromInt64(i int64) *AuthTime {
	return NewAuthTime(time.Unix(i, 0))
}

func (c AuthTime) ClaimName() string {
	return "auth_time"
}

// Nonce is a string value used to associate a client session with the token, and to mitigate replay attacks.
type Nonce string

func NewNonce(s string) *Nonce {
	return lo.ToPtr(Nonce(s))
}

func (c Nonce) ClaimName() string {
	return "nonce"
}

// Acr is the authentication context class reference.
type Acr string

func NewAcr(s string) *Acr {
	return lo.ToPtr(Acr(s))
}

func (c Acr) ClaimName() string {
	return "acr"
}

// Amr is the authentication methods references.
type Amr []string

func NewAmr(s []string) *Amr {
	return lo.ToPtr[Amr](s)
}

func (c Amr) ClaimName() string {
	return "amr"
}

// Azp is the authorized party - the party to which the token was issued.
type Azp string

func NewAzp(s string) *Azp {
	return lo.ToPtr(Azp(s))
}

func (c Azp) ClaimName() string {
	return "azp"
}
