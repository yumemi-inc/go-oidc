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

// Clone clones the claims bag.
func (c Claims) Clone() Claims {
	claims := NewClaims()
	for name, value := range c {
		claims[name] = value
	}

	return claims
}

func (c Claims) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]Claim(c))
}
