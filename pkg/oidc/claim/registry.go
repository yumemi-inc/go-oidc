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
	claim.AddUnmarshaler[Name](&DefaultRegistry)
	claim.AddUnmarshaler[GivenName](&DefaultRegistry)
	claim.AddUnmarshaler[FamilyName](&DefaultRegistry)
	claim.AddUnmarshaler[MiddleName](&DefaultRegistry)
	claim.AddUnmarshaler[Nickname](&DefaultRegistry)
	claim.AddUnmarshaler[PreferredUsername](&DefaultRegistry)
	claim.AddUnmarshaler[Profile](&DefaultRegistry)
	claim.AddUnmarshaler[Picture](&DefaultRegistry)
	claim.AddUnmarshaler[Website](&DefaultRegistry)
	claim.AddUnmarshaler[Email](&DefaultRegistry)
	claim.AddUnmarshaler[EmailVerified](&DefaultRegistry)
	claim.AddUnmarshaler[Gender](&DefaultRegistry)
	claim.AddUnmarshaler[Birthdate](&DefaultRegistry)
	claim.AddUnmarshaler[Zoneinfo](&DefaultRegistry)
	claim.AddUnmarshaler[Locale](&DefaultRegistry)
	claim.AddUnmarshaler[PhoneNumber](&DefaultRegistry)
	claim.AddUnmarshaler[PhoneNumberVerified](&DefaultRegistry)
	claim.AddUnmarshaler[UpdatedAt](&DefaultRegistry)
}
