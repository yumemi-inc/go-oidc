package claim

import (
	"encoding/json"
	"strings"

	"github.com/go-jose/go-jose/v3"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
)

func ClaimsFromSignedJWTWithRegistry(
	jwtString string,
	keychain jwt.PublicKeychain,
	registry Registrar,
) (Claims, error) {
	values := make(map[string]json.RawMessage)
	if err := jwt.Verify(jwtString, &values, keychain); err != nil {
		return nil, err
	}

	return registry.UnmarshalAll(values)
}

func ClaimsFromSignedJWT(jwt string, keychain jwt.PublicKeychain) (Claims, error) {
	return ClaimsFromSignedJWTWithRegistry(jwt, keychain, &DefaultRegistry)
}

func ClaimsFromEncryptedJWTWithRegistry(jwtString string, keychain jwt.Keychain, registry Registrar) (Claims, error) {
	values := make(map[string]json.RawMessage)
	if err := jwt.Decrypt(jwtString, &values, keychain); err != nil {
		return nil, err
	}

	return registry.UnmarshalAll(values)
}

func ClaimsFromEncryptedJWT(jwt string, keychain jwt.Keychain) (Claims, error) {
	return ClaimsFromEncryptedJWTWithRegistry(jwt, keychain, &DefaultRegistry)
}

func ClaimsFromJWTWithRegistry(jwt string, keychain jwt.Keychain, registry Registrar) (Claims, error) {
	if strings.Count(jwt, ".") == 4 {
		return ClaimsFromEncryptedJWTWithRegistry(jwt, keychain, registry)
	}

	return ClaimsFromSignedJWTWithRegistry(jwt, keychain, registry)
}

func ClaimsFromJWT(jwt string, keychain jwt.Keychain) (Claims, error) {
	return ClaimsFromJWTWithRegistry(jwt, keychain, &DefaultRegistry)
}

func UnsafeDecodeClaimsFromJWTWithRegistry(jwtString string, registry Registrar) (Claims, error) {
	values := make(map[string]json.RawMessage)
	if err := jwt.UnsafeDecodeSigned(jwtString, &values); err != nil {
		return nil, err
	}

	return registry.UnmarshalAll(values)
}

func UnsafeDecodeClaimsFromJWT(jwt string) (Claims, error) {
	return UnsafeDecodeClaimsFromJWTWithRegistry(jwt, &DefaultRegistry)
}

func (c Claims) SignJWT(key jwt.PrivateSigningKey) (string, error) {
	return jwt.Sign(c, key)
}

func (c Claims) EncryptJWT(key jwt.PublicEncryptionKey, encryption jose.ContentEncryption) (string, error) {
	return jwt.Encrypt(c, key, encryption)
}
