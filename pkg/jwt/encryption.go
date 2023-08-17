package jwt

import (
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
	Keychain

	PublicEncryptionKeys() []PublicEncryptionKey
	PublicEncryptionKey(id string) PublicEncryptionKey
}

type EncryptionKeychain interface {
	PublicEncryptionKeychain

	EncryptionKeypairs() []EncryptionKeypair
	EncryptionKeypair(id string) EncryptionKeypair
	PrivateEncryptionKeys() []PrivateEncryptionKey
	PrivateEncryptionKey(id string) PrivateEncryptionKey
}
