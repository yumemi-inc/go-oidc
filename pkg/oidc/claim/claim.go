package claim

import (
	"encoding/json"
	"errors"
	"fmt"
)

var (
	ErrKeyNotFound = errors.New("key not found in the keychain")
)

type Claim interface {
	ClaimName() string
}

type LocalizedClaim[T Claim] struct {
	Claim  T
	Locale string
}

func (c LocalizedClaim[T]) ClaimName() string {
	return fmt.Sprintf("%s#%s", c.Claim.ClaimName(), c.Locale)
}

func (c LocalizedClaim[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Claim)
}

func (c *LocalizedClaim[T]) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &c.Claim)
}

type CustomClaim[T any] struct {
	Name  string
	Value T
}

func (c CustomClaim[T]) ClaimName() string {
	return c.Name
}

func (c CustomClaim[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Value)
}

func (c *CustomClaim[T]) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &c.Value)
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
