package claim

import (
	"encoding/json"
	"errors"
)

var (
	ErrKeyNotFound = errors.New("key not found in the keychain")
)

type Claim interface {
	ClaimName() string
}

type CustomClaim[T any] struct {
	Name  string
	Value T
}

func (c CustomClaim[T]) ClaimName() string {
	return c.Name
}

type RawClaim = CustomClaim[json.RawMessage]

type Claims map[string]Claim

func NewClaims() Claims {
	return make(Claims)
}

func (c Claims) With(claim Claim) Claims {
	c[claim.ClaimName()] = claim

	return c
}

func (c Claims) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]Claim(c))
}
