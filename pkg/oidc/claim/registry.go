package claim

import (
	"github.com/yumemi-inc/go-oidc/pkg/jwt/claim"
)

type Registrar = claim.Registrar

var (
	DefaultRegistry = claim.DefaultRegistry.Clone()
)

func init() {
	claim.AddUnmarshaler[Iss](&DefaultRegistry)
	claim.AddUnmarshaler[Sub](&DefaultRegistry)
	claim.AddUnmarshaler[Aud](&DefaultRegistry)
	claim.AddUnmarshaler[Exp](&DefaultRegistry)
	claim.AddUnmarshaler[Iat](&DefaultRegistry)
	claim.AddUnmarshaler[AuthTime](&DefaultRegistry)
	claim.AddUnmarshaler[Nonce](&DefaultRegistry)
	claim.AddUnmarshaler[Acr](&DefaultRegistry)
	claim.AddUnmarshaler[Amr](&DefaultRegistry)
	claim.AddUnmarshaler[Azp](&DefaultRegistry)
}
