package claim

import (
	"github.com/yumemi-inc/go-oidc/pkg/jwt"
	"github.com/yumemi-inc/go-oidc/pkg/jwt/claim"
)

func ClaimsFromJWTWithRegistry(jwt string, keychain jwt.PublicKeychain, registry Registrar) (Claims, error) {
	claims, err := claim.ClaimsFromJWTWithRegistry(jwt, keychain, registry)
	if err != nil {
		return nil, err
	}

	return Claims(claims), nil
}

func ClaimsFromJWT(jwt string, keychain jwt.PublicKeychain) (Claims, error) {
	return ClaimsFromJWTWithRegistry(jwt, keychain, &DefaultRegistry)
}

func UnsafeDecodeClaimsFromJWTWithRegistry(jwt string, registry Registrar) (Claims, error) {
	claims, err := claim.UnsafeDecodeClaimsFromJWTWithRegistry(jwt, registry)
	if err != nil {
		return nil, err
	}

	return Claims(claims), nil
}

func UnsafeDecodeClaimsFromJWT(jwt string) (Claims, error) {
	return UnsafeDecodeClaimsFromJWTWithRegistry(jwt, &DefaultRegistry)
}

func (c Claims) SignJWT(key jwt.PrivateKey) (string, error) {
	return claim.Claims(c).SignJWT(key)
}
