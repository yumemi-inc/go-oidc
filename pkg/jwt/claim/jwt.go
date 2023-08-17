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
	object, err := jose.ParseSigned(jwtString)
	if err != nil {
		return nil, err
	}

	id := object.Signatures[0].Header.KeyID
	key, ok := keychain.PublicKey(id).(jwt.PublicSigningKey)
	if key == nil || !ok {
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

func ClaimsFromSignedJWT(jwt string, keychain jwt.PublicKeychain) (Claims, error) {
	return ClaimsFromSignedJWTWithRegistry(jwt, keychain, &DefaultRegistry)
}

func ClaimsFromEncryptedJWTWithRegistry(jwtString string, keychain jwt.Keychain, registry Registrar) (Claims, error) {
	object, err := jose.ParseEncrypted(jwtString)
	if err != nil {
		return nil, err
	}

	id := object.Header.KeyID
	key, ok := keychain.PrivateKey(id).(jwt.PrivateEncryptionKey)
	if key == nil || !ok {
		return nil, ErrKeyNotFound
	}

	bytes, err := object.Decrypt(key.PrivateKey())
	if err != nil {
		return nil, err
	}

	values := make(map[string]json.RawMessage)
	if err := json.Unmarshal(bytes, &values); err != nil {
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

func (c Claims) SignJWT(key jwt.PrivateSigningKey) (string, error) {
	bytes, err := c.MarshalJSON()
	if err != nil {
		return "", err
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: key.SigningAlgorithm(),
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

func (c Claims) EncryptJWT(key jwt.PublicEncryptionKey, encryption jose.ContentEncryption) (string, error) {
	bytes, err := c.MarshalJSON()
	if err != nil {
		return "", err
	}

	publicKey := jwt.JWKFromPublicKey(key)

	encrypter, err := jose.NewEncrypter(
		encryption,
		jose.Recipient{
			Algorithm: key.EncryptionKeyAlgorithm(),
			Key:       &publicKey,
		},
		nil,
	)
	if err != nil {
		return "", err
	}

	cipher, err := encrypter.Encrypt(bytes)
	if err != nil {
		return "", err
	}

	return cipher.CompactSerialize()
}
