package jwt

import (
	"encoding/json"

	"github.com/go-jose/go-jose/v3"
)

type SigningKey interface {
	Key

	SigningAlgorithm() jose.SignatureAlgorithm
}

type PublicSigningKey interface {
	SigningKey

	PublicKey() any
}

type PrivateSigningKey interface {
	SigningKey

	PrivateKey() any
}

type SigningKeypair interface {
	PublicSigningKey
	PrivateSigningKey
}

type PublicSigningKeychain interface {
	PublicKeychain

	PublicSigningKeys() []PublicSigningKey
	PublicSigningKey(id string) PublicSigningKey
}

type SigningKeychain interface {
	Keychain
	PublicSigningKeychain

	SigningKeypairs() []SigningKeypair
	SigningKeypair(id string) SigningKeypair
	PrivateSigningKeys() []PrivateSigningKey
	PrivateSigningKey(id string) PrivateSigningKey
}

// Sign signs the object and construct JWT using the signing key after serializing into JSON format.
func Sign(object any, key PrivateSigningKey) (string, error) {
	bytes, err := json.Marshal(object)
	if err != nil {
		return "", err
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: key.SigningAlgorithm(),
			Key:       JWKFromPrivateKey(key),
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

// Verify verifies the signed JWT and deserializes the payload from JSON format. While verification, it tries to parse
// the JWT header and finds a public signing key by their ID from the keychain. If no key found for the key ID, returns
// ErrKeyNotFound.
func Verify(jwt string, target any, keychain PublicKeychain) error {
	object, err := jose.ParseSigned(jwt)
	if err != nil {
		return err
	}

	id := object.Signatures[0].Header.KeyID
	key, ok := keychain.PublicKey(id).(PublicSigningKey)
	if key == nil || !ok {
		return ErrKeyNotFound
	}

	bytes, err := object.Verify(key.PublicKey())
	if err != nil {
		return err
	}

	return json.Unmarshal(bytes, target)
}

// UnsafeDecodeSigned decodes the signed JWT and deserializes the payload from JSON format. THIS DOES NOT PERFORM ANY
// VERIFICATION FOR THE SIGNATURE; DO NOT TRUST THE DECODED CONTENT.
func UnsafeDecodeSigned(jwt string, target any) error {
	object, err := jose.ParseSigned(jwt)
	if err != nil {
		return err
	}

	bytes := object.UnsafePayloadWithoutVerification()

	return json.Unmarshal(bytes, target)
}
