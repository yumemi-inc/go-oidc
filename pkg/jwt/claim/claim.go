package claim

import (
	"encoding/json"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
)

var (
	ErrKeyNotFound = jwt.ErrKeyNotFound
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

// Merge adds all values from another claims bag.
func (c Claims) Merge(claims Claims) Claims {
	for name, value := range claims {
		c[name] = value
	}

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

func (c *Claims) UnmarshalJSON(data []byte) error {
	values := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}

	claims, err := DefaultRegistry.UnmarshalAll(values)
	if err != nil {
		return err
	}

	*c = claims

	return nil
}
