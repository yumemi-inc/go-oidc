package claim

import (
	"encoding/json"
	"time"

	"github.com/samber/lo"
)

type Iss string

func NewIss(s string) *Iss {
	return lo.ToPtr(Iss(s))
}

func (c Iss) ClaimName() string {
	return "iss"
}

type Sub string

func NewSub(s string) *Sub {
	return lo.ToPtr(Sub(s))
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

type ClientID string

func NewClientID(s string) *ClientID {
	return lo.ToPtr(ClientID(s))
}

func (c ClientID) ClaimName() string {
	return "client_id"
}

// Exp is the expiration time on or after which the token MUST NOT be accepted for processing.
type Exp time.Time

func NewExp(t time.Time) *Exp {
	return lo.ToPtr(Exp(t))
}

func ExpFromInt64(i int64) *Exp {
	return NewExp(time.Unix(i, 0))
}

func (c Exp) Int64() int64 {
	return time.Time(c).Unix()
}

func (c Exp) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Int64())
}

func (c *Exp) UnmarshalJSON(data []byte) error {
	var i int64
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}

	e := ExpFromInt64(i)
	*c = *e

	return nil
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

func (c Iat) Int64() int64 {
	return time.Time(c).Unix()
}

func (c Iat) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Int64())
}

func (c *Iat) UnmarshalJSON(data []byte) error {
	var i int64
	if err := json.Unmarshal(data, &i); err != nil {
		return err
	}

	e := IatFromInt64(i)
	*c = *e

	return nil
}

func (c Iat) ClaimName() string {
	return "iat"
}

// Jti is a unique identifier for the JWT.
type Jti string

func NewJti(s string) *Jti {
	return lo.ToPtr(Jti(s))
}

func (c Jti) ClaimName() string {
	return "jti"
}
