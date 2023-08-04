package claim

import (
	"encoding/json"

	"github.com/go-jose/go-jose/v3"

	"github.com/yumemi-inc/go-oidc/pkg/jwt"
)

func ClaimsFromJWTWithRegistry(jwt string, keychain jwt.PublicKeychain, registry Registrar) (Claims, error) {
	object, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, err
	}

	id := object.Signatures[0].Header.KeyID
	key := keychain.PublicKey(id)
	if key == nil {
		return nil, ErrKeyNotFound
	}

	bytes, err := object.Verify(key.PublicKey())
	if err != nil {
		return nil, err
	}

	values := make(map[string]json.RawMessage)
	if err := json.Unmarshal(bytes, &values); err != nil {
		return nil, err
	}

	return registry.UnmarshalAll(values)
}

func ClaimsFromJWT(jwt string, keychain jwt.PublicKeychain) (Claims, error) {
	return ClaimsFromJWTWithRegistry(jwt, keychain, &DefaultRegistry)
}

func UnsafeDecodeClaimsFromJWTWithRegistry(jwt string, registry Registrar) (Claims, error) {
	object, err := jose.ParseSigned(jwt)
	if err != nil {
		return nil, err
	}

	bytes := object.UnsafePayloadWithoutVerification()

	values := make(map[string]json.RawMessage)
	if err := json.Unmarshal(bytes, &values); err != nil {
		return nil, err
	}

	return registry.UnmarshalAll(values)
}

func UnsafeDecodeClaimsFromJWT(jwt string) (Claims, error) {
	return UnsafeDecodeClaimsFromJWTWithRegistry(jwt, &DefaultRegistry)
}

func (c Claims) SignJWT(key jwt.PrivateKey) (string, error) {
	bytes, err := c.MarshalJSON()
	if err != nil {
		return "", err
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: key.Algorithm(),
			Key:       jwt.JWKFromPrivateKey(key),
		},
		nil,
	)
	if err != nil {
		return "", err
	}

	signature, err := signer.Sign(bytes)
	if err != nil {
		return "", err
	}

	return signature.CompactSerialize()
}
