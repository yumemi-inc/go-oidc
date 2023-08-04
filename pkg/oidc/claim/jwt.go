package claim

import (
	"github.com/yumemi-inc/go-oidc/pkg/jwt"
	"github.com/yumemi-inc/go-oidc/pkg/jwt/claim"
)

func ClaimsFromJWTWithRegistry(jwt string, keychain jwt.PublicKeychain, registry Registrar) (Claims, error) {
	return claim.ClaimsFromJWTWithRegistry(jwt, keychain, registry)
}

func ClaimsFromJWT(jwt string, keychain jwt.PublicKeychain) (Claims, error) {
	return ClaimsFromJWTWithRegistry(jwt, keychain, &DefaultRegistry)
}

func UnsafeDecodeClaimsFromJWTWithRegistry(jwt string, registry Registrar) (Claims, error) {
	return claim.UnsafeDecodeClaimsFromJWTWithRegistry(jwt, registry)
}

func UnsafeDecodeClaimsFromJWT(jwt string) (Claims, error) {
	return UnsafeDecodeClaimsFromJWTWithRegistry(jwt, &DefaultRegistry)
}
