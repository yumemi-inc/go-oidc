package claim

import (
	"encoding/json"
	"fmt"

	"github.com/yumemi-inc/go-oidc/pkg/jwt/claim"
)

type Claim = claim.Claim
type Claims = claim.Claims

func NewClaims() Claims {
	return claim.NewClaims()
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
