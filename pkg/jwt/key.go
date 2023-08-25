package jwt

import (
	"errors"

	"github.com/go-jose/go-jose/v3"
)

var (
	ErrKeyNotFound = errors.New("key not found in the keychain")
)

type Key interface {
	KeyID() string
}

type PublicKey interface {
	Key

	PublicKey() any
}

type PrivateKey interface {
	Key

	PrivateKey() any
}

type Keypair interface {
	PublicKey
	PrivateKey
}

type PublicKeychain interface {
	PublicKeys() []PublicKey
	PublicKey(id string) PublicKey
}

type Keychain interface {
	PublicKeychain

	Keypairs() []Keypair
	Keypair(id string) Keypair
	PrivateKeys() []PrivateKey
	PrivateKey(id string) PrivateKey
}

func getKey(key Key) any {
	switch key := key.(type) {
	case PublicKey:
		return key.PublicKey()

	case PrivateKey:
		return key.PrivateKey()

	default:
		panic("BUG: Unknown key type")
	}
}

func JWKFromEncryptionKey(key EncryptionKey) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       getKey(key),
		KeyID:     key.KeyID(),
		Algorithm: string(key.EncryptionKeyAlgorithm()),
		Use:       "enc",
	}
}

func JWKFromSigningKey(key SigningKey) jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       getKey(key),
		KeyID:     key.KeyID(),
		Algorithm: string(key.SigningAlgorithm()),
		Use:       "sig",
	}
}

func JWKSFromKeys(key ...Key) jose.JSONWebKeySet {
	keys := make([]jose.JSONWebKey, 0, len(key))
	for _, k := range key {
		if encryptionKey, ok := k.(EncryptionKey); ok {
			keys = append(keys, JWKFromEncryptionKey(encryptionKey))
		}

		if signingKey, ok := k.(SigningKey); ok {
			keys = append(keys, JWKFromSigningKey(signingKey))
		}
	}

	return jose.JSONWebKeySet{
		Keys: keys,
	}
}

func JWKFromPrivateKey(key PrivateKey) jose.JSONWebKey {
	var algorithm, use string
	switch key := key.(type) {
	case PrivateEncryptionKey:
		algorithm = string(key.EncryptionKeyAlgorithm())
		use = "enc"

	case PrivateSigningKey:
		algorithm = string(key.SigningAlgorithm())
		use = "sig"

	default:
		panic("BUG: Unsupported public key instance")
	}

	return jose.JSONWebKey{
		Key:       key.PrivateKey(),
		KeyID:     key.KeyID(),
		Algorithm: algorithm,
		Use:       use,
	}
}

func JWKSFromPublicKeychain(keychain PublicKeychain) jose.JSONWebKeySet {
	publicKeys := keychain.PublicKeys()
	keys := make([]Key, 0, len(publicKeys))
	for _, k := range publicKeys {
		keys = append(keys, k)
	}

	return JWKSFromKeys(keys...)
}
