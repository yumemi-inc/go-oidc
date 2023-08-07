package claim

import (
	"encoding/json"
	"fmt"

	"github.com/yumemi-inc/go-oidc/pkg/jwt/claim"
)

type Claim = claim.Claim
type Claims claim.Claims

func NewClaims() Claims {
	return Claims(claim.NewClaims())
}

func (c Claims) With(claim Claim) Claims {
	c[claim.ClaimName()] = claim

	return c
}

// Merge adds all values from another claims bag.
func (c Claims) Merge(claims Claims) Claims {
	return Claims(claim.Claims(c).Merge(claim.Claims(claims)))
}

// Clone clones the claims bag.
func (c Claims) Clone() Claims {
	return Claims(claim.Claims(c).Clone())
}

func (c Claims) MarshalJSON() ([]byte, error) {
	return claim.Claims(c).MarshalJSON()
}

func (c *Claims) UnmarshalJSON(data []byte) error {
	return (*claim.Claims)(c).UnmarshalJSON(data)
}

type LocalizedClaim[T claim.Claim] struct {
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
