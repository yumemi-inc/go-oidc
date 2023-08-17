package claim

import (
	"github.com/go-jose/go-jose/v3"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
	"github.com/yumemi-inc/go-oidc/pkg/jwt/claim"
)

func ClaimsFromSignedJWTWithRegistry(
	jwt string,
	keychain jwt.PublicKeychain,
	registry Registrar,
) (Claims, error) {
	claims, err := claim.ClaimsFromSignedJWTWithRegistry(jwt, keychain, registry)
	if err != nil {
		return nil, err
	}

	return Claims(claims), nil
}

func ClaimsFromSignedJWT(jwt string, keychain jwt.PublicKeychain) (Claims, error) {
	return ClaimsFromSignedJWTWithRegistry(jwt, keychain, &DefaultRegistry)
}

func ClaimsFromEncryptedJWTWithRegistry(
	jwt string,
	keychain jwt.Keychain,
	registry Registrar,
) (Claims, error) {
	claims, err := claim.ClaimsFromEncryptedJWTWithRegistry(jwt, keychain, registry)
	if err != nil {
		return nil, err
	}

	return Claims(claims), nil
}

func ClaimsFromEncryptedJWT(jwt string, keychain jwt.Keychain) (Claims, error) {
	return ClaimsFromEncryptedJWTWithRegistry(jwt, keychain, &DefaultRegistry)
}

func ClaimsFromJWTWithRegistry(
	jwt string,
	keychain jwt.Keychain,
	registry Registrar,
) (Claims, error) {
	claims, err := claim.ClaimsFromJWTWithRegistry(jwt, keychain, registry)
	if err != nil {
		return nil, err
	}

	return Claims(claims), nil
}

func ClaimsFromJWT(jwt string, keychain jwt.Keychain) (Claims, error) {
	return ClaimsFromEncryptedJWTWithRegistry(jwt, keychain, &DefaultRegistry)
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

func (c Claims) SignJWT(key jwt.PrivateSigningKey) (string, error) {
	return claim.Claims(c).SignJWT(key)
}

func (c Claims) EncryptJWT(key jwt.PublicEncryptionKey, encryption jose.ContentEncryption) (string, error) {
	return claim.Claims(c).EncryptJWT(key, encryption)
}
