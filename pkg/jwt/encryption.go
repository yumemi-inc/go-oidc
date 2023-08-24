package jwt

import (
	"encoding/json"

	"github.com/go-jose/go-jose/v3"
)

type EncryptionKey interface {
	Key

	EncryptionKeyAlgorithm() jose.KeyAlgorithm
}

type PublicEncryptionKey interface {
	EncryptionKey
	PublicKey
}

type PrivateEncryptionKey interface {
	EncryptionKey
	PrivateKey
}

type EncryptionKeypair interface {
	PublicEncryptionKey
	PrivateEncryptionKey
}

type PublicEncryptionKeychain interface {
	PublicKeychain

	PublicEncryptionKeys() []PublicEncryptionKey
	PublicEncryptionKey(id string) PublicEncryptionKey
}

type EncryptionKeychain interface {
	Keychain
	PublicEncryptionKeychain

	EncryptionKeypairs() []EncryptionKeypair
	EncryptionKeypair(id string) EncryptionKeypair
	PrivateEncryptionKeys() []PrivateEncryptionKey
	PrivateEncryptionKey(id string) PrivateEncryptionKey
}

// Encrypt encrypts the object and construct JWT using the encryption key after serializing into JSON format.
func Encrypt(object any, key PublicEncryptionKey, encryption jose.ContentEncryption) (string, error) {
	bytes, err := json.Marshal(object)
	if err != nil {
		return "", err
	}

	publicKey := JWKFromEncryptionKey(key)

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

// Decrypt decrypts the encrypted JWT and deserializes the payload from JSON format. While decryption, it tries to parse
// the JWT header and finds an encryption key by their ID from the keychain. If no key found for the key ID, returns
// ErrKeyNotFound.
func Decrypt(jwt string, target any, keychain Keychain) error {
	object, err := jose.ParseEncrypted(jwt)
	if err != nil {
		return err
	}

	id := object.Header.KeyID
	key, ok := keychain.PrivateKey(id).(PrivateEncryptionKey)
	if key == nil || !ok {
		return ErrKeyNotFound
	}

	bytes, err := object.Decrypt(key.PrivateKey())
	if err != nil {
		return err
	}

	return json.Unmarshal(bytes, target)
}
