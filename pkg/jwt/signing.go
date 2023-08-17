package jwt

import (
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
	Keychain

	PublicSigningKeys() []PublicSigningKey
	PublicSigningKey(id string) PublicSigningKey
}

type SigningKeychain interface {
	PublicSigningKeychain

	SigningKeypairs() []SigningKeypair
	SigningKeypair(id string) SigningKeypair
	PrivateSigningKeys() []PrivateSigningKey
	PrivateSigningKey(id string) PrivateSigningKey
}
