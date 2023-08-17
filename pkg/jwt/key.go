package jwt

import (
	"errors"

	"github.com/go-jose/go-jose/v3"
	"github.com/samber/lo"
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

func JWKFromPublicKey(key PublicKey) jose.JSONWebKey {
	var algorithm, use string
	switch key := key.(type) {
	case PublicEncryptionKey:
		algorithm = string(key.EncryptionKeyAlgorithm())
		use = "enc"

	case PublicSigningKey:
		algorithm = string(key.SigningAlgorithm())
		use = "sig"

	default:
		panic("BUG: Unsupported public key instance")
	}

	return jose.JSONWebKey{
		Key:       key.PublicKey(),
		KeyID:     key.KeyID(),
		Algorithm: algorithm,
		Use:       use,
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
	return jose.JSONWebKeySet{
		Keys: lo.Map(
			keychain.PublicKeys(),
			func(item PublicKey, _ int) jose.JSONWebKey {
				return JWKFromPublicKey(item)
			},
		),
	}
}
